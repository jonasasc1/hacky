package com.netaudit.scanner

/** Builds CSV / JSON exports for scan results. Pure string builders, no I/O. */
object Exporter {

    private fun esc(s: String?): String {
        val v = s ?: ""
        return "\"" + v.replace("\"", "\"\"") + "\""
    }

    private fun jesc(s: String?): String {
        val v = s ?: ""
        val sb = StringBuilder()
        for (c in v) when (c) {
            '\\' -> sb.append("\\\\")
            '"' -> sb.append("\\\"")
            '\n' -> sb.append("\\n")
            '\r' -> sb.append("\\r")
            '\t' -> sb.append("\\t")
            else -> if (c.code < 0x20) sb.append("\\u%04x".format(c.code)) else sb.append(c)
        }
        return sb.toString()
    }

    fun hostsCsv(hosts: List<Host>): String = buildString {
        appendLine("ip,hostname,mac,vendor,gateway")
        hosts.forEach {
            append(esc(it.ip)).append(',')
            append(esc(it.hostname)).append(',')
            append(esc(it.mac)).append(',')
            append(esc(it.vendor)).append(',')
            appendLine(if (it.isGateway) "true" else "false")
        }
    }

    fun hostsJson(hosts: List<Host>): String = buildString {
        append("[")
        hosts.forEachIndexed { i, h ->
            if (i > 0) append(",")
            append("{")
            append("\"ip\":\"").append(jesc(h.ip)).append("\",")
            append("\"hostname\":").append(h.hostname?.let { "\"${jesc(it)}\"" } ?: "null").append(",")
            append("\"mac\":").append(h.mac?.let { "\"${jesc(it)}\"" } ?: "null").append(",")
            append("\"vendor\":").append(h.vendor?.let { "\"${jesc(it)}\"" } ?: "null").append(",")
            append("\"gateway\":").append(h.isGateway)
            append("}")
        }
        append("]")
    }

    fun portsCsv(ip: String, ports: List<OpenPort>): String = buildString {
        appendLine("target,port,protocol,service,banner")
        ports.forEach {
            append(esc(ip)).append(',')
            append(it.port).append(',')
            append("tcp").append(',')
            append(esc(it.service)).append(',')
            appendLine(esc(it.banner))
        }
    }

    fun portsJson(ip: String, ports: List<OpenPort>): String = buildString {
        append("{\"target\":\"").append(jesc(ip)).append("\",\"open_ports\":[")
        ports.forEachIndexed { i, p ->
            if (i > 0) append(",")
            append("{\"port\":").append(p.port).append(",")
            append("\"protocol\":\"tcp\",")
            append("\"service\":\"").append(jesc(p.service)).append("\",")
            append("\"banner\":").append(p.banner?.let { "\"${jesc(it)}\"" } ?: "null")
            append("}")
        }
        append("]}")
    }
}
