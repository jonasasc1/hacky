package com.netaudit.scanner.vpn

/** Classifies the first bytes of a TCP stream and parses DNS, to spot plaintext vs TLS. */
object Classifier {

    enum class Kind { PLAINTEXT_HTTP, TLS, OTHER }
    data class TcpClass(val kind: Kind, val host: String?, val detail: String?)

    private val HTTP_METHODS = listOf("GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ")

    fun classifyTcp(payload: ByteArray, len: Int): TcpClass {
        if (len <= 0) return TcpClass(Kind.OTHER, null, null)
        val head = String(payload, 0, minOf(len, 8), Charsets.ISO_8859_1)
        if (HTTP_METHODS.any { head.startsWith(it) }) {
            val text = String(payload, 0, minOf(len, 1024), Charsets.ISO_8859_1)
            val reqLine = text.substringBefore("\r\n", "")
            val method = reqLine.substringBefore(' ')
            val path = reqLine.substringAfter(' ').substringBefore(' ').take(80)
            val host = Regex("(?im)^Host:\\s*(.+)$").find(text)?.groupValues?.get(1)?.trim()
            return TcpClass(Kind.PLAINTEXT_HTTP, host, "$method $path")
        }
        // TLS record: handshake(0x16), version 0x03 0x0x, then ClientHello(0x01)
        if (len > 5 && payload[0].toInt() and 0xFF == 0x16 && payload[1].toInt() and 0xFF == 0x03) {
            val sni = parseSni(payload, len)
            return TcpClass(Kind.TLS, sni, "TLS ClientHello")
        }
        return TcpClass(Kind.OTHER, null, null)
    }

    private fun parseSni(b: ByteArray, len: Int): String? {
        try {
            var p = 5                       // skip TLS record header
            if (p >= len || b[p].toInt() and 0xFF != 0x01) return null // ClientHello
            p += 4                          // handshake type + length(3)
            p += 2                          // client version
            p += 32                         // random
            if (p >= len) return null
            val sidLen = b[p].toInt() and 0xFF; p += 1 + sidLen
            if (p + 2 > len) return null
            val csLen = ((b[p].toInt() and 0xFF) shl 8) or (b[p + 1].toInt() and 0xFF); p += 2 + csLen
            if (p >= len) return null
            val compLen = b[p].toInt() and 0xFF; p += 1 + compLen
            if (p + 2 > len) return null
            val extTotal = ((b[p].toInt() and 0xFF) shl 8) or (b[p + 1].toInt() and 0xFF); p += 2
            val extEnd = minOf(p + extTotal, len)
            while (p + 4 <= extEnd) {
                val type = ((b[p].toInt() and 0xFF) shl 8) or (b[p + 1].toInt() and 0xFF)
                val elen = ((b[p + 2].toInt() and 0xFF) shl 8) or (b[p + 3].toInt() and 0xFF)
                p += 4
                if (type == 0x00) {         // server_name
                    var q = p + 2           // server name list length
                    if (q + 3 > len) return null
                    q += 1                  // name type
                    val nameLen = ((b[q].toInt() and 0xFF) shl 8) or (b[q + 1].toInt() and 0xFF); q += 2
                    if (q + nameLen > len) return null
                    return String(b, q, nameLen, Charsets.ISO_8859_1)
                }
                p += elen
            }
        } catch (_: Exception) {}
        return null
    }

    /** Parses a DNS question name (for logging the queried domain). */
    fun dnsQueryName(b: ByteArray, len: Int): String? {
        try {
            if (len < 13) return null
            var p = 12
            val sb = StringBuilder()
            while (p < len) {
                val l = b[p].toInt() and 0xFF
                if (l == 0) break
                if (sb.isNotEmpty()) sb.append('.')
                if (p + 1 + l > len) break
                sb.append(String(b, p + 1, l, Charsets.ISO_8859_1))
                p += 1 + l
            }
            return sb.toString().ifBlank { null }
        } catch (_: Exception) { return null }
    }

    /** Parses A records from a DNS response into (name -> ipString). */
    fun dnsAnswers(b: ByteArray, len: Int): List<Pair<String, String>> {
        val out = ArrayList<Pair<String, String>>()
        try {
            if (len < 12) return out
            val qd = ((b[4].toInt() and 0xFF) shl 8) or (b[5].toInt() and 0xFF)
            val an = ((b[6].toInt() and 0xFF) shl 8) or (b[7].toInt() and 0xFF)
            var p = 12
            fun skipName(start: Int): Int {
                var q = start
                while (q < len) {
                    val l = b[q].toInt() and 0xFF
                    if (l == 0) { q++; break }
                    if (l and 0xC0 == 0xC0) { q += 2; break }
                    q += 1 + l
                }
                return q
            }
            val qName = dnsQueryName(b, len) ?: ""
            repeat(qd) { p = skipName(p) + 4 }
            repeat(an) {
                if (p + 10 > len) return out
                p = skipName(p)
                if (p + 10 > len) return out
                val type = ((b[p].toInt() and 0xFF) shl 8) or (b[p + 1].toInt() and 0xFF)
                val rdlen = ((b[p + 8].toInt() and 0xFF) shl 8) or (b[p + 9].toInt() and 0xFF)
                val rd = p + 10
                if (type == 1 && rdlen == 4 && rd + 4 <= len) {
                    val ip = "${b[rd].toInt() and 0xFF}.${b[rd + 1].toInt() and 0xFF}." +
                        "${b[rd + 2].toInt() and 0xFF}.${b[rd + 3].toInt() and 0xFF}"
                    out.add(qName to ip)
                }
                p = rd + rdlen
            }
        } catch (_: Exception) {}
        return out
    }
}
