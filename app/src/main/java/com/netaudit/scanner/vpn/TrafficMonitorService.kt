package com.netaudit.scanner.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * Local VpnService that captures THIS device's own outbound traffic, forwards it
 * (so the phone stays online) and feeds TrafficLog. It cannot see other devices'
 * traffic — that is impossible without root. Opt-in; stop any time.
 */
class TrafficMonitorService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null
    private var out: FileOutputStream? = null
    private val writeLock = Any()
    private lateinit var tcp: TcpForwarder
    private lateinit var udp: UdpForwarder
    @Volatile private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { teardown(); stopSelf(); return START_NOT_STICKY }
        if (running) return START_STICKY
        start()
        return START_STICKY
    }

    private fun start() {
        val builder = Builder()
            .setSession("NetAudit")
            .addAddress("10.8.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .setMtu(1500)
        try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}
        val fd = try { builder.establish() } catch (_: Exception) { null } ?: run { stopSelf(); return }
        tun = fd
        out = FileOutputStream(fd.fileDescriptor)
        val writeTun: (ByteArray) -> Unit = { pkt ->
            synchronized(writeLock) { runCatching { out?.write(pkt); out?.flush() } }
        }
        tcp = TcpForwarder(this, writeTun).also { it.start() }
        udp = UdpForwarder(this, writeTun).also { it.start() }
        running = true
        TrafficLog.running = true
        reader = Thread({ readLoop(fd) }, "tun-read").apply { isDaemon = true; start() }
    }

    private fun readLoop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        while (running) {
            val n = try { input.read(buf) } catch (_: Exception) { break }
            if (n <= 0) { if (n < 0) break else continue }
            if (Packets.ipVersion(buf) != 4) continue
            val ipHl = Packets.ipHeaderLen(buf)
            if (ipHl < 20 || ipHl > n) continue
            val packet = buf.copyOf(n)
            when (Packets.ipProtocol(packet)) {
                Packets.PROTO_TCP -> runCatching { tcp.handle(packet, ipHl) }
                Packets.PROTO_UDP -> runCatching { udp.handle(packet, ipHl) }
            }
        }
    }

    private fun teardown() {
        running = false
        TrafficLog.running = false
        runCatching { if (this::tcp.isInitialized) tcp.stop() }
        runCatching { if (this::udp.isInitialized) udp.stop() }
        runCatching { out?.close() }
        runCatching { tun?.close() }
        tun = null
    }

    override fun onDestroy() { teardown(); super.onDestroy() }
    override fun onRevoke() { teardown(); stopSelf() }

    companion object {
        const val ACTION_STOP = "com.netaudit.scanner.vpn.STOP"
    }
}
