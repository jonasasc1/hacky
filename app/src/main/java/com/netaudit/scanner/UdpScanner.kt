package com.netaudit.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress

/**
 * Lightweight UDP service probes that a TCP scan cannot find: DNS, NTP, NetBIOS.
 * Returns open-service labels and any security findings (e.g. open DNS resolver).
 */
object UdpScanner {

    data class UdpResult(val labels: List<String>, val findings: List<Finding>)

    suspend fun scan(ip: String): UdpResult = withContext(Dispatchers.IO) {
        val labels = ArrayList<String>()
        val findings = ArrayList<Finding>()

        // DNS (53): recursion-desired A query for an external name
        dnsProbe(ip)?.let { answered ->
            labels.add("53/DNS")
            if (answered) findings.add(
                Finding(Severity.MEDIUM, "Offener DNS-Resolver", ip, 53,
                    "Beantwortet rekursive Anfragen für externe Namen. Kann für DNS-Amplification missbraucht werden – Rekursion auf interne Clients beschränken.", "Dienst")
            ) else findings.add(
                Finding(Severity.INFO, "DNS-Dienst (UDP) erreichbar", ip, 53,
                    "Antwortet auf DNS, aber nicht rekursiv für externe Namen.", "Dienst")
            )
        }

        // NTP (123)
        if (ntpProbe(ip)) {
            labels.add("123/NTP")
            findings.add(Finding(Severity.INFO, "NTP-Dienst (UDP) erreichbar", ip, 123,
                "Zeitdienst antwortet. Monlist/Amplification-Konfiguration prüfen.", "Dienst"))
        }

        // NetBIOS Name Service (137)
        netbiosProbe(ip)?.let { name ->
            labels.add("137/NetBIOS")
            findings.add(Finding(Severity.INFO, "NetBIOS-Name offengelegt", ip, 137,
                "NetBIOS-Name: $name. Auf modernen Netzen i. d. R. deaktivierbar.", "Information"))
        }

        UdpResult(labels, findings)
    }

    private fun txn(sock: DatagramSocket, ip: String, port: Int, payload: ByteArray, timeout: Int): ByteArray? {
        return try {
            sock.soTimeout = timeout
            sock.send(DatagramPacket(payload, payload.size, InetSocketAddress(ip, port)))
            val buf = ByteArray(2048)
            val resp = DatagramPacket(buf, buf.size)
            sock.receive(resp)
            resp.data.copyOf(resp.length)
        } catch (_: Exception) { null }
    }

    private fun dnsProbe(ip: String): Boolean? {
        val q = byteArrayOf(
            0x12, 0x34,              // id
            0x01, 0x00,              // flags: recursion desired
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // QNAME example.com
            7, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(),
            'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            3, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0,
            0x00, 0x01,              // QTYPE A
            0x00, 0x01               // QCLASS IN
        )
        DatagramSocket().use { s ->
            val r = txn(s, ip, 53, q, 1500) ?: return null
            if (r.size < 8) return null
            val qr = (r[2].toInt() and 0x80) != 0
            if (!qr) return null
            val ancount = ((r[6].toInt() and 0xff) shl 8) or (r[7].toInt() and 0xff)
            return ancount > 0   // true => it recursively resolved an external name
        }
    }

    private fun ntpProbe(ip: String): Boolean {
        val pkt = ByteArray(48); pkt[0] = 0x1b   // LI=0, VN=3, Mode=3 (client)
        DatagramSocket().use { s ->
            return txn(s, ip, 123, pkt, 1500) != null
        }
    }

    private fun netbiosProbe(ip: String): String? {
        // NBSTAT node status request for "*"
        val name = ByteArray(34)
        name[0] = 0x20
        // encode "*" + nulls -> 32 bytes of "CA" (0x2a -> 'C''K')
        val star = ByteArray(16); star[0] = '*'.code.toByte()
        var idx = 1
        for (b in star) {
            name[idx++] = ('A'.code + ((b.toInt() shr 4) and 0x0f)).toByte()
            name[idx++] = ('A'.code + (b.toInt() and 0x0f)).toByte()
        }
        name[33] = 0x00
        val header = byteArrayOf(
            0x13, 0x37, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        )
        val tail = byteArrayOf(0x00, 0x21, 0x00, 0x01) // QTYPE NBSTAT, QCLASS IN
        val q = header + name + tail
        DatagramSocket().use { s ->
            val r = txn(s, ip, 137, q, 1500) ?: return null
            if (r.size < 57) return null
            val num = r[56].toInt() and 0xff
            if (num <= 0) return null
            // first name entry starts at 57, 15 bytes name + 1 type byte + 2 flags
            val end = minOf(57 + 15, r.size)
            val nm = String(r, 57, end - 57, Charsets.ISO_8859_1).trim()
            return nm.ifBlank { "unbekannt" }
        }
    }
}
