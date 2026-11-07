package com.netaudit.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

data class OpenPort(
    val port: Int,
    val service: String,
    val banner: String?
)

object PortScanner {

    /** Well-known / frequently interesting TCP ports. */
    val COMMON_PORTS = intArrayOf(
        21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 389, 443,
        445, 465, 514, 515, 587, 631, 636, 873, 902, 993, 995, 1080, 1194,
        1433, 1521, 1723, 2049, 2082, 2375, 2376, 3000, 3306, 3389, 4444,
        5000, 5060, 5432, 5555, 5601, 5900, 5985, 6379, 6667, 7070, 8000,
        8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 27017
    )

    private val SERVICES = mapOf(
        21 to "FTP", 22 to "SSH", 23 to "Telnet", 25 to "SMTP", 53 to "DNS",
        80 to "HTTP", 110 to "POP3", 111 to "RPCbind", 123 to "NTP",
        135 to "MS-RPC", 139 to "NetBIOS", 143 to "IMAP", 161 to "SNMP",
        389 to "LDAP", 443 to "HTTPS", 445 to "SMB", 465 to "SMTPS",
        514 to "Syslog", 515 to "LPD", 587 to "SMTP-sub", 631 to "IPP",
        636 to "LDAPS", 873 to "rsync", 902 to "VMware", 993 to "IMAPS",
        995 to "POP3S", 1080 to "SOCKS", 1194 to "OpenVPN", 1433 to "MSSQL",
        1521 to "Oracle", 1723 to "PPTP", 2049 to "NFS", 2082 to "cPanel",
        2375 to "Docker", 2376 to "Docker-TLS", 3000 to "Dev/Grafana",
        3306 to "MySQL", 3389 to "RDP", 4444 to "Metasploit?", 5000 to "UPnP/Flask",
        5060 to "SIP", 5432 to "PostgreSQL", 5555 to "ADB", 5601 to "Kibana",
        5900 to "VNC", 5985 to "WinRM", 6379 to "Redis", 6667 to "IRC",
        7070 to "RTSP", 8000 to "HTTP-alt", 8008 to "HTTP-alt", 8080 to "HTTP-proxy",
        8081 to "HTTP-alt", 8443 to "HTTPS-alt", 8888 to "HTTP-alt", 9000 to "SonarQube/PHP-FPM",
        9090 to "Prometheus", 9200 to "Elasticsearch", 9300 to "ES-transport",
        10000 to "Webmin", 27017 to "MongoDB"
    )

    fun serviceName(port: Int): String = SERVICES[port] ?: "unknown"

    private val HTTP_PORTS = setOf(80, 8000, 8008, 8080, 8081, 8888, 3000, 5000, 9000, 9090, 10000)
    private val TLS_PORTS = setOf(443, 8443, 465, 636, 993, 995, 2376)

    private fun grabBanner(socket: Socket, port: Int): String? {
        return try {
            socket.soTimeout = 700
            if (port in HTTP_PORTS) {
                socket.getOutputStream().write(
                    "HEAD / HTTP/1.0\r\nHost: scan\r\n\r\n".toByteArray()
                )
                socket.getOutputStream().flush()
            }
            if (port in TLS_PORTS) {
                return "TLS/SSL (verschlüsselt)"
            }
            val buf = ByteArray(256)
            val n = socket.getInputStream().read(buf)
            if (n <= 0) return null
            val text = String(buf, 0, n)
                .replace(Regex("[\\r\\n]+"), " ")
                .filter { it.code in 32..126 }
                .trim()
            text.take(120).ifBlank { null }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Connect-scans [ports] on [ip]. Calls [onOpen] for each open port and [onProgress]
     * with (done,total). Runs on IO; cancel the enclosing coroutine to stop.
     */
    suspend fun scan(
        ip: String,
        ports: List<Int>,
        onOpen: suspend (OpenPort) -> Unit,
        onProgress: suspend (done: Int, total: Int) -> Unit
    ) = withContext(Dispatchers.IO) {
        val total = ports.size
        val sem = Semaphore(128)
        var done = 0
        val lock = Any()
        coroutineScope {
            for (port in ports) {
                launch {
                    sem.withPermit {
                        val sock = Socket()
                        try {
                            sock.connect(InetSocketAddress(ip, port), 450)
                            val banner = grabBanner(sock, port)
                            onOpen(OpenPort(port, serviceName(port), banner))
                        } catch (_: Exception) {
                            // closed / filtered
                        } finally {
                            try { sock.close() } catch (_: Exception) {}
                        }
                        val d = synchronized(lock) { ++done }
                        onProgress(d, total)
                    }
                }
            }
        }
    }
}
