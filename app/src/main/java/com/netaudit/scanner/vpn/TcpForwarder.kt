package com.netaudit.scanner.vpn

import android.net.VpnService
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.Random
import java.util.concurrent.ConcurrentHashMap

/**
 * Userspace TCP relay over the TUN. For each app TCP flow it opens a protected
 * socket to the real destination, synthesises TCP segments back to the app, and
 * classifies the first payload (plaintext HTTP vs TLS) for the traffic log.
 * Beta: a best-effort stack (no retransmit queue); stop the VPN to restore
 * normal networking if a flow misbehaves.
 */
class TcpForwarder(
    private val vpn: VpnService,
    private val tun: (ByteArray) -> Unit
) {
    private val MASK = 0xFFFFFFFFL
    private val MSS = 1460

    private inner class Conn(
        val clientIp: Int, val clientPort: Int,
        val remoteIp: Int, val remotePort: Int,
        val channel: SocketChannel, val myIsn: Long
    ) {
        var mySeq = myIsn
        var clientSeqNext = 0L
        @Volatile var established = false
        var firstInspected = false
        val key = "$clientPort>$remoteIp:$remotePort"
    }

    private val conns = ConcurrentHashMap<String, Conn>()
    private val selector: Selector = Selector.open()
    private val rnd = Random()
    @Volatile private var running = true

    fun start() { Thread({ loop() }, "tcp-fwd").apply { isDaemon = true }.start() }

    fun stop() {
        running = false
        selector.wakeup()
        conns.values.forEach { runCatching { it.channel.close() } }
        conns.clear()
        runCatching { selector.close() }
    }

    fun handle(packet: ByteArray, ipHl: Int) {
        val flags = Packets.tcpFlags(packet, ipHl)
        val clientIp = Packets.ipSrc(packet)
        val remoteIp = Packets.ipDst(packet)
        val clientPort = Packets.tcpSrcPort(packet, ipHl)
        val remotePort = Packets.tcpDstPort(packet, ipHl)
        val seq = Packets.tcpSeq(packet, ipHl)
        val key = "$clientPort>$remoteIp:$remotePort"
        val existing = conns[key]

        if (flags and Packets.SYN != 0 && existing == null) {
            try {
                val ch = SocketChannel.open()
                ch.configureBlocking(false)
                vpn.protect(ch.socket())
                val isn = rnd.nextInt().toLong() and MASK
                val c = Conn(clientIp, clientPort, remoteIp, remotePort, ch, isn)
                c.clientSeqNext = (seq + 1) and MASK
                conns[key] = c
                ch.connect(InetSocketAddress(Packets.ipToString(remoteIp), remotePort))
                synchronized(selector) {
                    selector.wakeup()
                    ch.register(selector, SelectionKey.OP_CONNECT, c)
                }
            } catch (_: Exception) {
                sendRst(clientIp, clientPort, remoteIp, remotePort, (seq + 1) and MASK)
            }
            return
        }
        val c = existing ?: return

        if (flags and Packets.RST != 0) { closeConn(c); return }

        val ipTotal = Packets.ipTotalLen(packet)
        val dataOff = ipHl + Packets.tcpDataOffset(packet, ipHl)
        val payloadLen = (ipTotal - dataOff).coerceAtLeast(0)

        if (payloadLen > 0) {
            synchronized(c) {
                when {
                    seq == c.clientSeqNext -> {
                        val payload = packet.copyOfRange(dataOff, dataOff + payloadLen)
                        if (!c.firstInspected) { c.firstInspected = true; classifyAndLog(c, payload) }
                        writeAll(c, payload)
                        c.clientSeqNext = (c.clientSeqNext + payloadLen) and MASK
                        sendAck(c)
                    }
                    else -> sendAck(c) // retransmit / out-of-order: just re-ack
                }
            }
        }

        if (flags and Packets.FIN != 0) {
            synchronized(c) {
                c.clientSeqNext = (c.clientSeqNext + 1) and MASK
                sendAck(c)
                runCatching { c.channel.socket().shutdownOutput() }
            }
        }
    }

    private fun classifyAndLog(c: Conn, payload: ByteArray) {
        val cls = Classifier.classifyTcp(payload, payload.size)
        val ipStr = Packets.ipToString(c.remoteIp)
        val domain = cls.host ?: TrafficLog.domainFor(ipStr)
        val insecure = cls.kind == Classifier.Kind.PLAINTEXT_HTTP
        val kind = when (cls.kind) {
            Classifier.Kind.PLAINTEXT_HTTP -> "HTTP (Klartext)"
            Classifier.Kind.TLS -> "TLS (verschlüsselt)"
            Classifier.Kind.OTHER -> "andere"
        }
        TrafficLog.add(TrafficEvent(System.currentTimeMillis(), "TCP", ipStr, c.remotePort,
            domain, kind, cls.detail, insecure))
    }

    private fun writeAll(c: Conn, data: ByteArray) {
        val bb = ByteBuffer.wrap(data)
        var tries = 0
        try {
            while (bb.hasRemaining() && tries++ < 2000) {
                if (c.channel.write(bb) == 0) Thread.sleep(1)
            }
        } catch (_: Exception) { closeConn(c) }
    }

    private fun loop() {
        val buf = ByteBuffer.allocate(MSS)
        while (running) {
            try { if (selector.select(1000) == 0) continue } catch (_: Exception) { break }
            val it = selector.selectedKeys().iterator()
            while (it.hasNext()) {
                val key = it.next(); it.remove()
                if (!key.isValid) continue
                val c = key.attachment() as? Conn ?: continue
                try {
                    if (key.isConnectable) {
                        if (c.channel.finishConnect()) {
                            synchronized(c) {
                                sendSynAck(c)
                                c.mySeq = (c.myIsn + 1) and MASK
                                c.established = true
                            }
                            key.interestOps(SelectionKey.OP_READ)
                        }
                    } else if (key.isReadable) {
                        buf.clear()
                        val n = c.channel.read(buf)
                        if (n > 0) {
                            buf.flip(); val data = ByteArray(n); buf.get(data)
                            synchronized(c) {
                                sendData(c, data)
                                c.mySeq = (c.mySeq + n) and MASK
                            }
                        } else if (n < 0) {
                            synchronized(c) {
                                sendFin(c)
                                c.mySeq = (c.mySeq + 1) and MASK
                            }
                            closeConn(c)
                        }
                    }
                } catch (_: Exception) {
                    synchronized(c) { sendRst(c.clientIp, c.clientPort, c.remoteIp, c.remotePort, c.clientSeqNext) }
                    closeConn(c)
                }
            }
        }
    }

    // ---- segment senders (remote -> app) ----
    private fun sendSynAck(c: Conn) = tun(Packets.buildTcp(
        c.remoteIp, c.clientIp, c.remotePort, c.clientPort,
        c.myIsn, c.clientSeqNext, Packets.SYN or Packets.ACK, null))

    private fun sendAck(c: Conn) = tun(Packets.buildTcp(
        c.remoteIp, c.clientIp, c.remotePort, c.clientPort,
        c.mySeq, c.clientSeqNext, Packets.ACK, null))

    private fun sendData(c: Conn, data: ByteArray) = tun(Packets.buildTcp(
        c.remoteIp, c.clientIp, c.remotePort, c.clientPort,
        c.mySeq, c.clientSeqNext, Packets.PSH or Packets.ACK, data))

    private fun sendFin(c: Conn) = tun(Packets.buildTcp(
        c.remoteIp, c.clientIp, c.remotePort, c.clientPort,
        c.mySeq, c.clientSeqNext, Packets.FIN or Packets.ACK, null))

    private fun sendRst(clientIp: Int, clientPort: Int, remoteIp: Int, remotePort: Int, ack: Long) =
        tun(Packets.buildTcp(remoteIp, clientIp, remotePort, clientPort, 0, ack, Packets.RST or Packets.ACK, null))

    private fun closeConn(c: Conn) {
        runCatching { c.channel.close() }
        conns.remove(c.key)
    }
}
