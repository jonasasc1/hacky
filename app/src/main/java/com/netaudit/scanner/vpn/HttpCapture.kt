package com.netaudit.scanner.vpn

import android.util.Base64
import java.util.Collections

/** A sensitive item a network attacker could read from a plaintext connection. */
data class SensitiveHit(val label: String, val value: String)

/**
 * Captures the readable plaintext of ONE unencrypted HTTP connection (request +
 * response), capped in size, and extracts what an on-path attacker could harvest
 * (credentials, cookies, tokens, form/query fields). Only used for cleartext HTTP;
 * TLS content is never available (that's the whole point of the contrast).
 */
class HttpCapture(val id: String, val host: String, val port: Int) {
    val startedAt = System.currentTimeMillis()
    @Volatile var method: String? = null
    @Volatile var path: String? = null
    private val req = StringBuilder()
    private val resp = StringBuilder()
    private val cap = 24 * 1024

    @Synchronized
    fun appendRequest(data: ByteArray, off: Int, len: Int) {
        appendTo(req, data, off, len)
        if (method == null) parseRequestLine()
    }

    @Synchronized
    fun appendResponse(data: ByteArray, off: Int, len: Int) = appendTo(resp, data, off, len)

    private fun appendTo(sb: StringBuilder, data: ByteArray, off: Int, len: Int) {
        if (sb.length >= cap) return
        val take = minOf(len, cap - sb.length)
        for (i in off until off + take) {
            val c = data[i].toInt() and 0xFF
            sb.append(if (c == 0x0A || c == 0x0D || c == 0x09 || c in 0x20..0x7E) c.toChar() else '.')
        }
    }

    private fun parseRequestLine() {
        val line = req.toString().substringBefore("\r\n", "")
        val parts = line.split(' ')
        if (parts.size >= 2 && parts[0].all { it.isLetter() }) {
            method = parts[0]; path = parts[1].take(200)
        }
    }

    @Synchronized fun requestText(): String = req.toString()
    @Synchronized fun responseText(): String = resp.toString()

    /** Everything an attacker on the same network could read from this flow. */
    @Synchronized
    fun sensitive(): List<SensitiveHit> {
        val hits = ArrayList<SensitiveHit>()
        val reqText = req.toString()
        val respText = resp.toString()

        // Request headers
        header(reqText, "authorization")?.let { auth ->
            if (auth.startsWith("Basic ", true)) {
                val dec = try {
                    String(Base64.decode(auth.substring(6).trim(), Base64.DEFAULT))
                } catch (_: Exception) { "" }
                hits.add(SensitiveHit("Login im Klartext (Basic-Auth)", dec.ifBlank { auth }))
            } else {
                hits.add(SensitiveHit("Auth-Token", auth.take(80)))
            }
        }
        header(reqText, "cookie")?.let { hits.add(SensitiveHit("Session-Cookie (Übernahme möglich)", it.take(120))) }
        header(reqText, "x-api-key")?.let { hits.add(SensitiveHit("API-Key", it.take(80))) }
        header(reqText, "x-auth-token")?.let { hits.add(SensitiveHit("Auth-Token", it.take(80))) }
        header(respText, "set-cookie")?.let { hits.add(SensitiveHit("Server setzt Cookie (abgreifbar)", it.take(120))) }

        // Query string + body form/JSON fields
        val reqLine = reqText.substringBefore("\r\n", "")
        val query = reqLine.substringAfter('?', "").substringBefore(' ')
        val body = reqText.substringAfter("\r\n\r\n", "")
        for (src in listOf(query, body)) {
            if (src.isBlank()) continue
            for (m in Regex("(?i)(pass(word|wd)?|pwd|secret|token|api[_-]?key|auth|session|email|user(name)?)[=\":\\s]+([^&\"'\\s]{2,80})").findAll(src)) {
                val key = m.groupValues[1]
                val value = m.groupValues.last()
                hits.add(SensitiveHit("Feld '$key'", value))
            }
        }
        // de-duplicate
        return hits.distinctBy { it.label + it.value }.take(20)
    }

    private fun header(text: String, name: String): String? {
        val m = Regex("(?im)^$name:\\s*(.+)$").find(text) ?: return null
        return m.groupValues[1].trim()
    }
}

/** Bounded, process-wide store of captured plaintext HTTP exchanges. */
object HttpCaptureStore {
    private const val MAX = 80
    private val map = Collections.synchronizedMap(object : LinkedHashMap<String, HttpCapture>() {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, HttpCapture>) = size > MAX
    })

    fun create(id: String, host: String, port: Int): HttpCapture {
        val c = HttpCapture(id, host, port)
        map[id] = c
        return c
    }

    fun get(id: String?): HttpCapture? = if (id == null) null else map[id]
    fun clear() = map.clear()
}
