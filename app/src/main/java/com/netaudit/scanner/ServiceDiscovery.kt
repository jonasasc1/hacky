package com.netaudit.scanner

import android.content.Context
import android.net.wifi.WifiManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import kotlin.coroutines.coroutineContext

data class Discovered(
    val source: String,     // "mDNS" or "SSDP"
    val ip: String?,
    val title: String,
    val subtitle: String
)

/**
 * Passive/active service discovery that finds devices which do not answer a port scan:
 *  - mDNS / DNS-SD (Bonjour): printers, Chromecast, AirPlay, HomeKit, SMB, SSH ...
 *  - SSDP / UPnP: routers, smart TVs, NAS, IoT gateways ...
 * Both need a Wi-Fi multicast lock, acquired here for the duration of the scan.
 */
object ServiceDiscovery {

    private const val MDNS_ADDR = "224.0.0.251"
    private const val MDNS_PORT = 5353
    private const val SSDP_ADDR = "239.255.255.250"
    private const val SSDP_PORT = 1900

    private val MDNS_SERVICE_TYPES = listOf(
        "_services._dns-sd._udp.local",
        "_http._tcp.local", "_https._tcp.local",
        "_ipp._tcp.local", "_ipps._tcp.local", "_printer._tcp.local",
        "_pdl-datastream._tcp.local", "_scanner._tcp.local",
        "_googlecast._tcp.local", "_airplay._tcp.local", "_raop._tcp.local",
        "_spotify-connect._tcp.local", "_sonos._tcp.local",
        "_workstation._tcp.local", "_ssh._tcp.local", "_sftp-ssh._tcp.local",
        "_smb._tcp.local", "_afpovertcp._tcp.local", "_nfs._tcp.local",
        "_device-info._tcp.local", "_homekit._tcp.local", "_hap._tcp.local",
        "_companion-link._tcp.local", "_rfb._tcp.local"
    )

    suspend fun discover(
        context: Context,
        durationMs: Long,
        onFound: suspend (Discovered) -> Unit,
        onStatus: suspend (String) -> Unit
    ) = withContext(Dispatchers.IO) {
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        val lock = wifi?.createMulticastLock("netaudit-discovery")?.apply {
            setReferenceCounted(true); acquire()
        }
        try {
            onStatus("mDNS / DNS-SD …")
            runCatching { mdns(durationMs / 2, onFound) }
            if (!coroutineContext.isActive) return@withContext
            onStatus("SSDP / UPnP …")
            runCatching { ssdp(durationMs / 2, onFound) }
        } finally {
            try { lock?.release() } catch (_: Exception) {}
        }
    }

    // ---------------- mDNS ----------------

    private suspend fun mdns(durationMs: Long, onFound: suspend (Discovered) -> Unit) {
        val group = InetAddress.getByName(MDNS_ADDR)
        val socket = MulticastSocket(null)
        try {
            socket.reuseAddress = true
            socket.bind(InetSocketAddress(MDNS_PORT))
            socket.soTimeout = 400
            @Suppress("DEPRECATION")
            socket.joinGroup(group)

            val query = buildMdnsQuery(MDNS_SERVICE_TYPES)
            socket.send(DatagramPacket(query, query.size, group, MDNS_PORT))

            val seen = HashSet<String>()
            val names = HashMap<String, String>()   // hostname -> ip
            val deadline = System.currentTimeMillis() + durationMs
            val buf = ByteArray(9000)
            while (System.currentTimeMillis() < deadline && coroutineContext.isActive) {
                val pkt = DatagramPacket(buf, buf.size)
                try {
                    socket.receive(pkt)
                } catch (_: Exception) {
                    continue
                }
                val records = runCatching { parseDns(pkt.data, pkt.length) }.getOrNull() ?: continue
                // first pass: collect A records
                for (r in records) {
                    val ip = r.ipv4
                    if (r.type == 1 && ip != null) names[r.name.lowercase()] = ip
                }
                // second pass: emit SRV + PTR + plain A
                for (r in records) {
                    when (r.type) {
                        33 -> { // SRV
                            val target = r.target
                            val ip = names[(target ?: "").lowercase()]
                            val key = "srv:${r.name}"
                            if (seen.add(key)) onFound(
                                Discovered(
                                    "mDNS", ip,
                                    r.name.removeSuffix(".local"),
                                    "${serviceOf(r.name)} • ${target ?: "?"}:${r.port}"
                                )
                            )
                        }
                        12 -> { // PTR
                            val ptr = r.ptr
                            if (ptr != null && !ptr.startsWith("_")) {
                                val key = "ptr:$ptr"
                                if (seen.add(key)) onFound(
                                    Discovered(
                                        "mDNS", null,
                                        ptr.removeSuffix(".local"),
                                        serviceOf(ptr)
                                    )
                                )
                            }
                        }
                    }
                }
                for ((host, ip) in names) {
                    val key = "a:$host"
                    if (seen.add(key)) onFound(
                        Discovered("mDNS", ip, host.removeSuffix(".local"), "mDNS host")
                    )
                }
            }
            @Suppress("DEPRECATION")
            runCatching { socket.leaveGroup(group) }
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun serviceOf(name: String): String {
        val m = Regex("(_[a-z0-9-]+\\._(?:tcp|udp))").find(name) ?: return "service"
        return m.groupValues[1]
    }

    private fun buildMdnsQuery(types: List<String>): ByteArray {
        val out = ByteArrayOutputStream()
        // header: id=0, flags=0, qd=count, an/ns/ar=0
        out.write(0); out.write(0)
        out.write(0); out.write(0)
        out.write(types.size ushr 8); out.write(types.size and 0xff)
        out.write(0); out.write(0); out.write(0); out.write(0); out.write(0); out.write(0)
        for (t in types) {
            for (label in t.split(".")) {
                val b = label.toByteArray(Charsets.UTF_8)
                out.write(b.size); out.write(b)
            }
            out.write(0)           // end of name
            out.write(0); out.write(12)  // QTYPE = PTR
            out.write(0); out.write(1)   // QCLASS = IN (QM response)
        }
        return out.toByteArray()
    }

    private class Rec(
        val name: String, val type: Int,
        var ipv4: String? = null, var ptr: String? = null,
        var target: String? = null, var port: Int = 0
    )

    private fun parseDns(data: ByteArray, len: Int): List<Rec> {
        fun u16(p: Int) = ((data[p].toInt() and 0xff) shl 8) or (data[p + 1].toInt() and 0xff)
        // read a (possibly compressed) name starting at off; returns name + next offset
        fun readName(start: Int): Pair<String, Int> {
            val sb = StringBuilder()
            var p = start
            var next = -1
            var guard = 0
            while (p < len && guard++ < 128) {
                val l = data[p].toInt() and 0xff
                if (l == 0) { p++; if (next < 0) next = p; break }
                if (l and 0xc0 == 0xc0) {
                    val ptr = ((l and 0x3f) shl 8) or (data[p + 1].toInt() and 0xff)
                    if (next < 0) next = p + 2
                    p = ptr
                    continue
                }
                if (p + 1 + l > len) break
                if (sb.isNotEmpty()) sb.append('.')
                sb.append(String(data, p + 1, l, Charsets.UTF_8))
                p += 1 + l
            }
            if (next < 0) next = p
            return sb.toString() to next
        }

        val out = ArrayList<Rec>()
        val qd = u16(4); val an = u16(6); val ns = u16(8); val ar = u16(10)
        var p = 12
        repeat(qd) {
            val (_, n) = readName(p); p = n + 4  // skip qtype+qclass
        }
        val totalRR = an + ns + ar
        repeat(totalRR) {
            if (p >= len) return out
            val (name, n) = readName(p); p = n
            if (p + 10 > len) return out
            val type = u16(p); p += 2
            p += 2 // class
            p += 4 // ttl
            val rdlen = u16(p); p += 2
            val rdStart = p
            val rec = Rec(name, type)
            when (type) {
                1 -> if (rdlen == 4) rec.ipv4 =
                    "${data[p].toInt() and 0xff}.${data[p + 1].toInt() and 0xff}." +
                        "${data[p + 2].toInt() and 0xff}.${data[p + 3].toInt() and 0xff}"
                12 -> rec.ptr = readName(p).first
                33 -> {
                    rec.port = u16(p + 4)
                    rec.target = readName(p + 6).first
                }
            }
            out.add(rec)
            p = rdStart + rdlen
        }
        return out
    }

    // ---------------- SSDP ----------------

    private suspend fun ssdp(durationMs: Long, onFound: suspend (Discovered) -> Unit) {
        val group = InetAddress.getByName(SSDP_ADDR)
        val socket = MulticastSocket(null)
        try {
            socket.reuseAddress = true
            socket.bind(InetSocketAddress(0))
            socket.soTimeout = 400
            val msearch = (
                "M-SEARCH * HTTP/1.1\r\n" +
                    "HOST: $SSDP_ADDR:$SSDP_PORT\r\n" +
                    "MAN: \"ssdp:discover\"\r\n" +
                    "MX: 2\r\n" +
                    "ST: ssdp:all\r\n\r\n"
                ).toByteArray(Charsets.US_ASCII)
            repeat(2) {
                socket.send(DatagramPacket(msearch, msearch.size, group, SSDP_PORT))
            }

            val seen = HashSet<String>()
            val deadline = System.currentTimeMillis() + durationMs
            val buf = ByteArray(2048)
            while (System.currentTimeMillis() < deadline && coroutineContext.isActive) {
                val pkt = DatagramPacket(buf, buf.size)
                try {
                    socket.receive(pkt)
                } catch (_: Exception) {
                    continue
                }
                val ip = pkt.address?.hostAddress ?: continue
                val text = String(pkt.data, 0, pkt.length, Charsets.US_ASCII)
                val headers = parseHeaders(text)
                val server = headers["server"]
                val st = headers["st"] ?: headers["nt"]
                val location = headers["location"]
                val key = "$ip|${st ?: ""}"
                if (seen.add(key)) {
                    onFound(
                        Discovered(
                            "SSDP", ip,
                            server ?: (st ?: "UPnP-Gerät"),
                            listOfNotNull(st?.takeIf { server != null }, location)
                                .joinToString(" • ").ifBlank { "UPnP" }
                        )
                    )
                }
            }
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun parseHeaders(text: String): Map<String, String> {
        val map = HashMap<String, String>()
        for (line in text.split("\r\n")) {
            val i = line.indexOf(':')
            if (i > 0) map[line.substring(0, i).trim().lowercase()] = line.substring(i + 1).trim()
        }
        return map
    }
}
