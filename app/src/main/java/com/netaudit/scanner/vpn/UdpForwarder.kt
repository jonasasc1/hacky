package com.netaudit.scanner.vpn

import android.net.VpnService
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.concurrent.ConcurrentHashMap

/** Userspace UDP NAT: forwards datagrams via protected channels and logs DNS. */
class UdpForwarder(
    private val vpn: VpnService,
    private val tun: (ByteArray) -> Unit
) {
    private class Session(
        val channel: DatagramChannel,
        val clientIp: Int, val clientPort: Int,
        val remoteIp: Int, val remotePort: Int
    ) { @Volatile var lastUse = System.currentTimeMillis() }

    private val sessions = ConcurrentHashMap<String, Session>()
    private val selector: Selector = Selector.open()
    @Volatile private var running = true

    fun start() {
        Thread({ loop() }, "udp-fwd").apply { isDaemon = true }.start()
    }

    fun stop() {
        running = false
        selector.wakeup()
        sessions.values.forEach { runCatching { it.channel.close() } }
        sessions.clear()
        runCatching { selector.close() }
    }

    fun handle(packet: ByteArray, ipHl: Int) {
        val clientIp = Packets.ipSrc(packet)
        val remoteIp = Packets.ipDst(packet)
        val clientPort = ((packet[ipHl].toInt() and 0xFF) shl 8) or (packet[ipHl + 1].toInt() and 0xFF)
        val remotePort = ((packet[ipHl + 2].toInt() and 0xFF) shl 8) or (packet[ipHl + 3].toInt() and 0xFF)
        val payloadOff = ipHl + 8
        val total = Packets.ipTotalLen(packet)
        if (payloadOff > total || total > packet.size) return
        val payload = packet.copyOfRange(payloadOff, total)

        val key = "$clientPort>$remoteIp:$remotePort"
        var s = sessions[key]
        if (s == null) {
            val ch = DatagramChannel.open()
            vpn.protect(ch.socket())
            ch.configureBlocking(false)
            ch.connect(InetSocketAddress(Packets.ipToString(remoteIp), remotePort))
            s = Session(ch, clientIp, clientPort, remoteIp, remotePort)
            sessions[key] = s
            synchronized(selector) {
                selector.wakeup()
                ch.register(selector, SelectionKey.OP_READ, s)
            }
        }
        s.lastUse = System.currentTimeMillis()
        if (remotePort == 53) {
            Classifier.dnsQueryName(payload, payload.size)?.let { name ->
                TrafficLog.add(TrafficEvent(System.currentTimeMillis(), "DNS",
                    Packets.ipToString(remoteIp), 53, name, "DNS", "Anfrage", false))
            }
        }
        runCatching { s.channel.write(ByteBuffer.wrap(payload)) }
    }

    private fun loop() {
        val buf = ByteBuffer.allocate(32767)
        while (running) {
            try {
                if (selector.select(1000) == 0) { evict(); continue }
            } catch (_: Exception) { break }
            val it = selector.selectedKeys().iterator()
            while (it.hasNext()) {
                val key = it.next(); it.remove()
                if (!key.isValid) continue
                val s = key.attachment() as? Session ?: continue
                if (key.isReadable) {
                    buf.clear()
                    val n = try { (key.channel() as DatagramChannel).read(buf) } catch (_: Exception) { -1 }
                    if (n <= 0) continue
                    buf.flip()
                    val data = ByteArray(n); buf.get(data)
                    s.lastUse = System.currentTimeMillis()
                    if (s.remotePort == 53) {
                        for ((name, ip) in Classifier.dnsAnswers(data, data.size)) TrafficLog.rememberDns(name, ip)
                    }
                    // build UDP packet remote->client
                    val pkt = Packets.buildUdp(s.remoteIp, s.clientIp, s.remotePort, s.clientPort, data)
                    tun(pkt)
                }
            }
            evict()
        }
    }

    private fun evict() {
        val now = System.currentTimeMillis()
        val dead = sessions.filterValues { now - it.lastUse > 30000 }
        for ((k, s) in dead) { runCatching { s.channel.close() }; sessions.remove(k) }
    }
}
