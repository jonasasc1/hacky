package com.netaudit.scanner

import android.annotation.SuppressLint
import android.content.Context
import android.net.wifi.WifiManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket

data class WifiNet(
    val ipv4: Inet4Address,
    val prefix: Int,
    val gateway: String?,
    val ssid: String?
)

data class Host(
    val ip: String,
    val ipInt: Int,
    var hostname: String? = null,
    var mac: String? = null,
    var isGateway: Boolean = false
)

object NetworkUtils {

    /** Returns the active Wi-Fi IPv4 config, or null if not connected to a usable network. */
    @SuppressLint("MissingPermission", "DefaultLocale")
    fun currentWifiNet(context: Context): WifiNet? {
        var found: Pair<Inet4Address, Int>? = null
        try {
            for (nif in NetworkInterface.getNetworkInterfaces()) {
                if (!nif.isUp || nif.isLoopback) continue
                for (ia in nif.interfaceAddresses) {
                    val addr = ia.address
                    if (addr is Inet4Address && addr.isSiteLocalAddress) {
                        found = addr to ia.networkPrefixLength.toInt()
                        break
                    }
                }
                if (found != null) break
            }
        } catch (_: Exception) {
        }
        val (ip, prefix) = found ?: return null

        val wifi = context.applicationContext
            .getSystemService(Context.WIFI_SERVICE) as? WifiManager
        @Suppress("DEPRECATION")
        val dhcp = wifi?.dhcpInfo
        val gateway = dhcp?.gateway?.takeIf { it != 0 }?.let { intToIp(it) }
        @Suppress("DEPRECATION")
        val ssidRaw = wifi?.connectionInfo?.ssid
        val ssid = ssidRaw?.trim('"')?.takeIf {
            it.isNotBlank() && it != "<unknown ssid>"
        }
        return WifiNet(ip, prefix, gateway, ssid)
    }

    private fun ipToInt(addr: InetAddress): Int {
        val b = addr.address
        return (b[0].toInt() and 0xff shl 24) or
            (b[1].toInt() and 0xff shl 16) or
            (b[2].toInt() and 0xff shl 8) or
            (b[3].toInt() and 0xff)
    }

    fun intToIp(v: Int): String =
        "${v ushr 24 and 0xff}.${v ushr 16 and 0xff}.${v ushr 8 and 0xff}.${v and 0xff}"

    private fun intToInet(v: Int): InetAddress = InetAddress.getByAddress(
        byteArrayOf(
            (v ushr 24 and 0xff).toByte(),
            (v ushr 16 and 0xff).toByte(),
            (v ushr 8 and 0xff).toByte(),
            (v and 0xff).toByte()
        )
    )

    /** Computes the scannable host-address range for the given net, clamped to /24 if large. */
    fun hostRange(net: WifiNet): IntRange {
        val ipInt = ipToInt(net.ipv4)
        val prefix = net.prefix.coerceIn(1, 32)
        val mask = if (prefix == 0) 0 else (-1 shl (32 - prefix))
        var network = ipInt and mask
        var broadcast = network or mask.inv()
        var start = network + 1
        var end = broadcast - 1
        if (end - start > 1022) { // too big: scan the host's own /24 only
            network = ipInt and (-1 shl 8)
            start = network + 1
            end = network + 254
        }
        return start..end
    }

    /** Reads /proc/net/arp (best effort; restricted on newer Android) into ip->mac. */
    private fun readArpTable(): Map<String, String> {
        val map = HashMap<String, String>()
        try {
            File("/proc/net/arp").bufferedReader().useLines { lines ->
                lines.drop(1).forEach { line ->
                    val cols = line.trim().split(Regex("\\s+"))
                    if (cols.size >= 4) {
                        val ip = cols[0]
                        val mac = cols[3]
                        if (mac != "00:00:00:00:00:00" && mac.contains(':')) {
                            map[ip] = mac.uppercase()
                        }
                    }
                }
            }
        } catch (_: Exception) {
        }
        return map
    }

    /** TCP "knock": host is considered up if a common port connects or actively refuses. */
    private fun tcpAlive(ip: String): Boolean {
        for (port in intArrayOf(80, 443, 22, 445, 139, 53, 8080)) {
            Socket().use { s ->
                try {
                    s.connect(InetSocketAddress(ip, port), 300)
                    return true // connected -> up
                } catch (e: java.net.ConnectException) {
                    val m = e.message ?: ""
                    if (m.contains("refused", true) || m.contains("ECONNREFUSED", true)) {
                        return true // refused -> host exists
                    }
                } catch (_: Exception) {
                    // timeout / unreachable -> try next port
                }
            }
        }
        return false
    }

    /**
     * Discovers live hosts on the subnet. Invokes [onHost] (on caller's context) for each
     * host as it is found, and [onProgress] with (done,total). Honour cancellation by
     * launching inside a cancellable coroutine scope.
     */
    suspend fun discoverHosts(
        net: WifiNet,
        onHost: suspend (Host) -> Unit,
        onProgress: suspend (done: Int, total: Int) -> Unit
    ) = withContext(Dispatchers.IO) {
        val arp = readArpTable()
        val range = hostRange(net)
        val total = range.count()
        val gatewayIp = net.gateway
        val sem = Semaphore(64)
        var done = 0
        coroutineScope {
            for (ipInt in range) {
                launch {
                    sem.withPermit {
                        val ipStr = intToIp(ipInt)
                        var up = false
                        try {
                            if (intToInet(ipInt).isReachable(350)) up = true
                        } catch (_: Exception) {
                        }
                        if (!up) up = tcpAlive(ipStr)
                        if (!up && arp.containsKey(ipStr)) up = true

                        if (up) {
                            val host = Host(ip = ipStr, ipInt = ipInt)
                            host.mac = arp[ipStr]
                            host.isGateway = (ipStr == gatewayIp)
                            host.hostname = withTimeoutOrNull(500) {
                                val n = intToInet(ipInt).canonicalHostName
                                if (n != ipStr) n else null
                            }
                            onHost(host)
                        }
                        synchronized(this@NetworkUtils) { done++ }
                        onProgress(done, total)
                    }
                }
            }
        }
    }
}
