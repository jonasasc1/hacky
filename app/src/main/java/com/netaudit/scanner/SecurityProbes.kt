package com.netaudit.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * Read-only security probes for an authorised self-audit. These DETECT weak
 * configuration (plaintext transport, open unauthenticated services, outdated
 * TLS); they do NOT brute-force credentials or exploit anything. The only
 * guessed value used is the documented default SNMP community "public", which
 * is a standard configuration-disclosure check.
 */
object SecurityProbes {

    private val HTTP_PORTS = setOf(80, 8000, 8008, 8080, 8081, 8888, 3000, 5000, 9090, 10000)
    private val HTTPS_PORTS = setOf(443, 8443)

    suspend fun probePort(op: OpenPort, ip: String): List<Finding> = withContext(Dispatchers.IO) {
        val f = ArrayList<Finding>()
        try {
            when (op.port) {
                23 -> {
                    op.insecure = true; op.info = "Klartext-Fernzugriff"
                    f += Finding(Severity.HIGH, "Telnet im Klartext", ip, 23,
                        "Telnet überträgt Anmeldedaten und Sitzung unverschlüsselt. Durch SSH ersetzen.", "Klartext")
                }
                21 -> {
                    op.insecure = true; op.info = "FTP (Klartext, außer FTPS)"
                    f += Finding(Severity.MEDIUM, "FTP ohne garantierte Verschlüsselung", ip, 21,
                        "FTP überträgt Zugangsdaten normalerweise im Klartext. FTPS/SFTP verwenden.", "Klartext")
                }
                25, 110, 143 -> {
                    f += Finding(Severity.LOW, "Mail-Dienst – STARTTLS prüfen", ip, op.port,
                        "Port ${op.port} offen. Sicherstellen, dass STARTTLS erzwungen wird.", "Klartext")
                }
                in HTTP_PORTS -> f += httpProbe(ip, op, tls = false)
                in HTTPS_PORTS -> f += tlsProbe(ip, op) + httpProbe(ip, op, tls = true)
                6379 -> f += redisProbe(ip, op)
                9200 -> f += elasticProbe(ip, op)
                5900 -> f += vncProbe(ip, op)
                27017 -> f += Finding(Severity.MEDIUM, "MongoDB-Port offen", ip, 27017,
                    "MongoDB erreichbar. Authentifizierung und Bind-Adresse prüfen.", "Dienst")
                3389 -> f += Finding(Severity.LOW, "RDP offen", ip, 3389,
                    "Remote Desktop erreichbar. NLA erzwingen, Zugriff einschränken.", "Dienst")
                445 -> f += smbProbe(ip, op)
            }
        } catch (_: Exception) {
        }
        f
    }

    // ---- HTTP ----
    private fun httpProbe(ip: String, op: OpenPort, tls: Boolean): List<Finding> {
        val f = ArrayList<Finding>()
        val resp = try {
            if (tls) httpOverTls(ip, op.port) else httpPlain(ip, op.port)
        } catch (_: Exception) { null } ?: return f

        val server = resp.headers["server"]
        val title = resp.title
        op.info = buildString {
            append(if (tls) "HTTPS" else "HTTP")
            if (resp.status > 0) append(" ${resp.status}")
            if (server != null) append(" • $server")
            if (title != null) append(" • \"$title\"")
        }
        if (!tls) {
            op.insecure = true
            f += Finding(Severity.MEDIUM, "Unverschlüsseltes HTTP", ip, op.port,
                "Der Webdienst überträgt Daten im Klartext (kein TLS). Inhalte und ggf. Cookies/Logins sind mitlesbar." +
                    (server?.let { " Server: $it." } ?: ""), "Klartext")
            val authH = resp.headers["www-authenticate"]
            if (authH != null && authH.contains("basic", true)) {
                f += Finding(Severity.HIGH, "Basic-Auth über unverschlüsseltes HTTP", ip, op.port,
                    "Zugangsdaten werden Base64-kodiert im Klartext übertragen und sind trivial mitlesbar.", "Klartext")
            }
        } else {
            if (resp.headers["strict-transport-security"] == null) {
                f += Finding(Severity.LOW, "HSTS-Header fehlt", ip, op.port,
                    "Kein Strict-Transport-Security – Downgrade auf HTTP möglich.", "TLS")
            }
        }
        if (server != null && server.any { it.isDigit() }) {
            f += Finding(Severity.INFO, "Server-Version offengelegt", ip, op.port,
                "Server-Header: $server", "Information")
        }
        deviceHint(server, title)?.let { hint ->
            f += Finding(Severity.INFO, "Admin-/Geräte-Oberfläche erkannt", ip, op.port,
                "$hint. Standard-Zugangsdaten ändern und Zugriff einschränken.", "Information")
        }
        return f
    }

    private val DEVICE_HINTS = mapOf(
        "fritz" to "FRITZ!Box-Router", "tp-link" to "TP-Link-Gerät", "tplink" to "TP-Link-Gerät",
        "routeros" to "MikroTik RouterOS", "dd-wrt" to "DD-WRT-Router", "openwrt" to "OpenWrt-Router",
        "ubnt" to "Ubiquiti-Gerät", "unifi" to "Ubiquiti UniFi", "hikvision" to "Hikvision-Kamera",
        "dahua" to "Dahua-Kamera", "axis" to "Axis-Kamera", "jenkins" to "Jenkins (CI)",
        "grafana" to "Grafana", "phpmyadmin" to "phpMyAdmin", "synology" to "Synology NAS",
        "qnap" to "QNAP NAS", "printer" to "Drucker-Weboberfläche", "jetdirect" to "HP-Drucker",
        "webmin" to "Webmin", "pi-hole" to "Pi-hole", "proxmox" to "Proxmox"
    )

    private fun deviceHint(server: String?, title: String?): String? {
        val hay = ("${server ?: ""} ${title ?: ""}").lowercase()
        for ((k, v) in DEVICE_HINTS) if (hay.contains(k)) return v
        return null
    }

    // ---- SMB / SMBv1 ----
    private fun smbProbe(ip: String, op: OpenPort): List<Finding> {
        val f = ArrayList<Finding>()
        f += Finding(Severity.LOW, "SMB-Dateifreigabe offen", ip, 445,
            "Port 445 erreichbar. Zugriff einschränken und SMB-Signierung erzwingen.", "Dienst")
        try {
            Socket().use { s ->
                s.connect(InetSocketAddress(ip, 445), 2000)
                s.soTimeout = 2000
                val req = smbv1NegotiatePacket()
                s.getOutputStream().write(req); s.getOutputStream().flush()
                val buf = ByteArray(512)
                val n = s.getInputStream().read(buf)
                if (n > 8) {
                    // NetBIOS(4) + SMB header: 0xFF 'S' 'M' 'B', command 0x72 = negotiate response
                    val smb = n > 8 && buf[4].toInt() and 0xff == 0xFF &&
                        buf[5].toInt() == 'S'.code && buf[6].toInt() == 'M'.code &&
                        buf[7].toInt() == 'B'.code && buf[8].toInt() and 0xff == 0x72
                    if (smb) {
                        op.insecure = true; op.info = "SMBv1 aktiv"
                        f += Finding(Severity.HIGH, "SMBv1 aktiviert", ip, 445,
                            "Der Server antwortet auf das veraltete SMBv1-Protokoll (EternalBlue-Risiko). SMBv1 deaktivieren.", "Dienst")
                    }
                }
            }
        } catch (_: Exception) {
        }
        return f
    }

    private fun smbv1NegotiatePacket(): ByteArray {
        val dialects = listOf(
            "PC NETWORK PROGRAM 1.0", "LANMAN1.0", "Windows for Workgroups 3.1a",
            "LM1.2X002", "LANMAN2.1", "NT LM 0.12"
        )
        val body = ByteArrayOutputStream()
        for (d in dialects) { body.write(0x02); body.write(d.toByteArray()); body.write(0) }
        val bytes = body.toByteArray()
        val smb = ByteArrayOutputStream()
        smb.write(0xFF); smb.write('S'.code); smb.write('M'.code); smb.write('B'.code)
        smb.write(0x72)                                   // COM_NEGOTIATE
        smb.write(byteArrayOf(0, 0, 0, 0))                // status
        smb.write(0x18); smb.write(byteArrayOf(0x01, 0x28)) // flags, flags2
        smb.write(ByteArray(12))                          // pidHigh + signature
        smb.write(ByteArray(2))                           // reserved
        smb.write(ByteArray(2)); smb.write(ByteArray(2))  // tid, pid
        smb.write(ByteArray(2)); smb.write(ByteArray(2))  // uid, mid
        smb.write(0x00)                                   // word count
        smb.write(bytes.size and 0xff); smb.write((bytes.size ushr 8) and 0xff) // byte count
        smb.write(bytes)
        val smbBytes = smb.toByteArray()
        val out = ByteArrayOutputStream()
        out.write(0x00)                                   // NetBIOS session message
        out.write((smbBytes.size ushr 16) and 0xff)
        out.write((smbBytes.size ushr 8) and 0xff)
        out.write(smbBytes.size and 0xff)
        out.write(smbBytes)
        return out.toByteArray()
    }

    private data class HttpResp(val status: Int, val headers: Map<String, String>, val title: String?)

    private fun readHttp(s: Socket, ip: String, port: Int): HttpResp {
        s.soTimeout = 2500
        s.getOutputStream().write(
            ("GET / HTTP/1.1\r\nHost: $ip\r\nUser-Agent: NetAudit\r\nConnection: close\r\n\r\n")
                .toByteArray()
        )
        s.getOutputStream().flush()
        val buf = ByteArrayOutputStream()
        val tmp = ByteArray(4096)
        val input = s.getInputStream()
        var total = 0
        while (total < 16384) {
            val n = try { input.read(tmp) } catch (_: Exception) { -1 }
            if (n <= 0) break
            buf.write(tmp, 0, n); total += n
        }
        val text = buf.toString("ISO-8859-1")
        val headEnd = text.indexOf("\r\n\r\n")
        val head = if (headEnd >= 0) text.substring(0, headEnd) else text
        val body = if (headEnd >= 0) text.substring(headEnd + 4) else ""
        val lines = head.split("\r\n")
        val status = Regex("HTTP/\\d\\.\\d\\s+(\\d+)").find(lines.firstOrNull() ?: "")
            ?.groupValues?.get(1)?.toIntOrNull() ?: -1
        val headers = HashMap<String, String>()
        for (i in 1 until lines.size) {
            val c = lines[i].indexOf(':')
            if (c > 0) headers[lines[i].substring(0, c).trim().lowercase()] = lines[i].substring(c + 1).trim()
        }
        val title = Regex("<title[^>]*>(.*?)</title>", RegexOption.IGNORE_CASE)
            .find(body)?.groupValues?.get(1)?.trim()?.take(60)?.ifBlank { null }
        return HttpResp(status, headers, title)
    }

    private fun httpPlain(ip: String, port: Int): HttpResp {
        Socket().use { s ->
            s.connect(InetSocketAddress(ip, port), 2000)
            return readHttp(s, ip, port)
        }
    }

    private fun httpOverTls(ip: String, port: Int): HttpResp {
        trustAllFactory().createSocket().use { raw ->
            raw.connect(InetSocketAddress(ip, port), 2500)
            val ssl = raw as SSLSocket
            ssl.startHandshake()
            return readHttp(ssl, ip, port)
        }
    }

    // ---- TLS ----
    private fun tlsProbe(ip: String, op: OpenPort): List<Finding> {
        val f = ArrayList<Finding>()
        try {
            (trustAllFactory().createSocket() as SSLSocket).use { ssl ->
                ssl.connect(InetSocketAddress(ip, op.port), 2500)
                ssl.soTimeout = 2500
                ssl.startHandshake()
                val sess = ssl.session
                val proto = sess.protocol
                val cert = sess.peerCertificates.firstOrNull() as? X509Certificate
                op.info = "TLS $proto"
                if (proto in setOf("SSLv3", "TLSv1", "TLSv1.1")) {
                    op.insecure = true
                    f += Finding(Severity.HIGH, "Veraltetes TLS-Protokoll", ip, op.port,
                        "Aushandlung über $proto. Mindestens TLS 1.2 erzwingen.", "TLS")
                }
                if (cert != null) {
                    val now = Date()
                    if (cert.notAfter.before(now)) {
                        f += Finding(Severity.HIGH, "TLS-Zertifikat abgelaufen", ip, op.port,
                            "Gültig bis ${cert.notAfter}.", "TLS")
                    } else if (cert.notAfter.time - now.time < 30L * 24 * 3600 * 1000) {
                        f += Finding(Severity.LOW, "TLS-Zertifikat läuft bald ab", ip, op.port,
                            "Gültig bis ${cert.notAfter}.", "TLS")
                    }
                    if (cert.issuerX500Principal == cert.subjectX500Principal) {
                        f += Finding(Severity.INFO, "Selbstsigniertes Zertifikat", ip, op.port,
                            "Subject: ${cert.subjectX500Principal.name}", "TLS")
                    }
                    val key = cert.publicKey
                    val bits = Regex("(\\d+)").findAll(key.toString())
                        .map { it.value.toInt() }.filter { it >= 512 }.maxOrNull() ?: 0
                    if (key.algorithm == "RSA" && bits in 1 until 2048) {
                        f += Finding(Severity.MEDIUM, "Schwacher TLS-Schlüssel", ip, op.port,
                            "RSA-Schlüssellänge ~$bits bit (< 2048).", "TLS")
                    }
                }
            }
        } catch (_: Exception) {
        }
        return f
    }

    private fun trustAllFactory() = SSLContext.getInstance("TLS").apply {
        init(null, arrayOf(object : X509TrustManager {
            override fun checkClientTrusted(c: Array<out X509Certificate>?, a: String?) {}
            override fun checkServerTrusted(c: Array<out X509Certificate>?, a: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }), SecureRandom())
    }.socketFactory

    // ---- Redis ----
    private fun redisProbe(ip: String, op: OpenPort): List<Finding> {
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress(ip, op.port), 2000)
                s.soTimeout = 2000
                s.getOutputStream().write("*1\r\n\$4\r\nINFO\r\n".toByteArray())
                s.getOutputStream().flush()
                val buf = ByteArray(256)
                val n = s.getInputStream().read(buf)
                val r = if (n > 0) String(buf, 0, n) else ""
                when {
                    r.contains("redis_version") || r.startsWith("$") -> {
                        op.insecure = true; op.info = "Redis ohne Auth"
                        listOf(Finding(Severity.HIGH, "Redis ohne Authentifizierung", ip, op.port,
                            "Redis antwortet ohne Login auf INFO – voller Datenzugriff möglich. requirepass/ACL setzen, Bind einschränken.", "Dienst"))
                    }
                    r.contains("NOAUTH") -> {
                        op.info = "Redis (Auth aktiv)"
                        listOf(Finding(Severity.INFO, "Redis mit Authentifizierung", ip, op.port,
                            "Redis verlangt ein Passwort (gut).", "Dienst"))
                    }
                    else -> emptyList()
                }
            }
        } catch (_: Exception) { emptyList() }
    }

    // ---- Elasticsearch ----
    private fun elasticProbe(ip: String, op: OpenPort): List<Finding> {
        return try {
            val resp = httpPlain(ip, op.port)
            if (resp.status in 200..299) {
                op.insecure = true; op.info = "Elasticsearch offen"
                listOf(Finding(Severity.HIGH, "Elasticsearch ohne Authentifizierung", ip, op.port,
                    "Cluster-API ohne Login erreichbar – Daten lesbar/änderbar. Security aktivieren.", "Dienst"))
            } else emptyList()
        } catch (_: Exception) { emptyList() }
    }

    // ---- VNC ----
    private fun vncProbe(ip: String, op: OpenPort): List<Finding> {
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress(ip, op.port), 2000)
                s.soTimeout = 2000
                val inp = s.getInputStream()
                val hello = ByteArray(12)
                if (inp.read(hello) < 12) return emptyList()
                val ver = String(hello).trim()
                s.getOutputStream().write("RFB 003.008\n".toByteArray()); s.getOutputStream().flush()
                val nTypes = inp.read()
                if (nTypes <= 0) {
                    op.info = "VNC $ver"
                    return emptyList()
                }
                val types = ByteArray(nTypes); inp.read(types)
                val noneAuth = types.any { it.toInt() == 1 }
                op.info = "VNC $ver"
                if (noneAuth) {
                    op.insecure = true
                    listOf(Finding(Severity.HIGH, "VNC ohne Authentifizierung", ip, op.port,
                        "Der VNC-Server bietet Security-Type \"None\" – Bildschirmzugriff ohne Passwort möglich.", "Dienst"))
                } else emptyList()
            }
        } catch (_: Exception) { emptyList() }
    }

    // ---- SNMP (UDP 161, default community "public", read-only sysDescr) ----
    fun snmpPublicCheck(ip: String): Finding? {
        return try {
            // minimal SNMPv2c GET of 1.3.6.1.2.1.1.1.0 with community "public"
            val pkt = snmpGetSysDescr("public")
            DatagramSocket().use { sock ->
                sock.soTimeout = 1500
                sock.send(DatagramPacket(pkt, pkt.size, InetSocketAddress(ip, 161)))
                val buf = ByteArray(2048)
                val resp = DatagramPacket(buf, buf.size)
                sock.receive(resp)
                // any well-formed response to "public" means the default community works
                val desc = extractSnmpString(resp.data, resp.length)
                Finding(Severity.HIGH, "SNMP mit Default-Community \"public\"", ip, 161,
                    "Gerät antwortet auf SNMP mit der Standard-Community \"public\" (lesend)." +
                        (desc?.let { " sysDescr: $it" } ?: "") +
                        " Community ändern oder SNMP deaktivieren.", "Klartext")
            }
        } catch (_: Exception) { null }
    }

    private fun snmpGetSysDescr(community: String): ByteArray {
        // OID 1.3.6.1.2.1.1.1.0
        val oid = byteArrayOf(0x2b, 6, 1, 2, 1, 1, 1, 0)
        val varbind = tlv(0x30, tlv(0x06, oid) + tlv(0x05, ByteArray(0)))
        val varbinds = tlv(0x30, varbind)
        val pdu = tlv(0xa0,
            tlv(0x02, byteArrayOf(0x1a, 0x2b, 0x3c, 0x4d)) +  // request id
                tlv(0x02, byteArrayOf(0)) +                   // error status
                tlv(0x02, byteArrayOf(0)) +                   // error index
                varbinds)
        return tlv(0x30,
            tlv(0x02, byteArrayOf(1)) +                       // version 2c (=1)
                tlv(0x04, community.toByteArray()) +
                pdu)
    }

    private fun tlv(tag: Int, value: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag)
        if (value.size < 128) out.write(value.size) else {
            val lenBytes = value.size
            out.write(0x82); out.write(lenBytes ushr 8); out.write(lenBytes and 0xff)
        }
        out.write(value)
        return out.toByteArray()
    }

    private fun extractSnmpString(data: ByteArray, len: Int): String? {
        // crude: find the last OCTET STRING (0x04) with printable content
        var i = 0
        var best: String? = null
        while (i < len - 2) {
            if (data[i].toInt() and 0xff == 0x04) {
                val l = data[i + 1].toInt() and 0xff
                if (l in 1..127 && i + 2 + l <= len) {
                    val s = String(data, i + 2, l, Charsets.ISO_8859_1)
                    if (s.all { it.code in 32..126 } && s.length > 3) best = s
                }
            }
            i++
        }
        return best?.take(80)
    }
}
