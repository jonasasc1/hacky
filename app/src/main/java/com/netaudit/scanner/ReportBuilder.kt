package com.netaudit.scanner

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Builds shareable reports (self-contained HTML, CSV, JSON) from an AuditResult. */
object ReportBuilder {

    private fun ts(t: Long) =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.GERMANY).format(Date(t))

    private fun h(s: String?): String = (s ?: "").replace("&", "&amp;")
        .replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    fun html(r: AuditResult): String {
        val sb = StringBuilder()
        val sevColors = mapOf(
            Severity.CRITICAL to "#d32f2f", Severity.HIGH to "#f4511e",
            Severity.MEDIUM to "#f9a825", Severity.LOW to "#1e88e5", Severity.INFO to "#757575"
        )
        sb.append(
            """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetAudit Report</title>
<style>
:root{color-scheme:light dark}
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#fafafa;color:#1a1a1a}
@media(prefers-color-scheme:dark){body{background:#121212;color:#e8e8e8}.card{background:#1e1e1e!important;border-color:#333!important}th{background:#262626!important}}
header{background:#0d47a1;color:#fff;padding:24px 20px}
header h1{margin:0 0 4px;font-size:22px}
.meta{font-size:13px;opacity:.9}
.wrap{max-width:900px;margin:0 auto;padding:16px}
.card{background:#fff;border:1px solid #e0e0e0;border-radius:12px;padding:16px;margin:12px 0}
.counts{display:flex;flex-wrap:wrap;gap:8px}
.chip{color:#fff;border-radius:999px;padding:6px 12px;font-size:13px;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px;border-bottom:1px solid #e0e0e0;vertical-align:top}
th{background:#f0f0f0}
.sev{font-weight:700;white-space:nowrap}
code{font-family:ui-monospace,monospace}
.small{font-size:12px;opacity:.7}
</style></head><body>
<header><h1>NetAudit – Netzwerk-Audit-Report</h1>
<div class="meta">SSID: ${h(r.ssid ?: "—")} &nbsp;•&nbsp; Lokale IP: ${h(r.localIp)} &nbsp;•&nbsp; Gateway: ${h(r.gateway ?: "—")}<br>
Bereich: ${h(r.rangeFrom)}–${h(r.rangeTo)} &nbsp;•&nbsp; ${ts(r.startedAt)} → ${ts(r.finishedAt)}</div></header>
<div class="wrap">
"""
        )
        // summary
        sb.append("""<div class="card"><h3>Zusammenfassung</h3><div class="counts">""")
        for (s in Severity.values()) {
            val c = r.countBy(s)
            if (c > 0) sb.append("""<span class="chip" style="background:${sevColors[s]}">${s.label}: $c</span>""")
        }
        sb.append("""<span class="chip" style="background:#455a64">Hosts: ${r.hosts.size}</span>""")
        sb.append("""<span class="chip" style="background:#455a64">Offene Ports: ${r.openPortCount()}</span>""")
        sb.append("</div></div>")

        // findings
        sb.append("""<div class="card"><h3>Findings (${r.findings.size})</h3><table>
<tr><th>Schwere</th><th>Titel</th><th>Host:Port</th><th>Detail</th></tr>""")
        for (f in r.findings) {
            val hp = if (f.port == 0) h(f.host) else "${h(f.host)}:${f.port}"
            sb.append("""<tr><td class="sev" style="color:${sevColors[f.severity]}">${f.severity.label}</td>
<td>${h(f.title)}</td><td><code>$hp</code></td><td>${h(f.detail)}</td></tr>""")
        }
        if (r.findings.isEmpty()) sb.append("""<tr><td colspan="4">Keine Findings.</td></tr>""")
        sb.append("</table></div>")

        // hosts
        sb.append("""<div class="card"><h3>Hosts & offene Ports</h3><table>
<tr><th>IP</th><th>Name / Hersteller</th><th>TCP (offen)</th><th>UDP</th></tr>""")
        for (ha in r.hosts) {
            val ports = ha.openPorts.joinToString(", ") {
                val mark = if (it.insecure) " ⚠" else ""
                "${it.port}/${it.service}$mark"
            }
            val udp = ha.udpPorts.joinToString(", ")
            val name = listOfNotNull(ha.host.hostname, ha.host.vendor).joinToString(" • ")
            sb.append("""<tr><td><code>${h(ha.host.ip)}</code>${if (ha.host.isGateway) " <span class=small>(GW)</span>" else ""}</td>
<td>${h(name)}</td><td>${h(ports)}</td><td>${h(udp)}</td></tr>""")
        }
        sb.append("</table></div>")

        // discovered services
        if (r.services.isNotEmpty()) {
            sb.append("""<div class="card"><h3>Dienste (mDNS/SSDP)</h3><table>
<tr><th>Quelle</th><th>Name</th><th>Details</th></tr>""")
            for (d in r.services) sb.append(
                """<tr><td>${h(d.source)}</td><td>${h(d.title)}</td><td class="small">${h(listOfNotNull(d.ip, d.subtitle).joinToString(" • "))}</td></tr>"""
            )
            sb.append("</table></div>")
        }

        sb.append("""<p class="small">Erstellt mit NetAudit. Nur für autorisiertes Testen eigener/freigegebener Netze.</p></div></body></html>""")
        return sb.toString()
    }

    fun csv(r: AuditResult): String = buildString {
        appendLine("severity,title,host,port,category,detail")
        fun esc(s: String?) = "\"" + (s ?: "").replace("\"", "\"\"") + "\""
        for (f in r.findings) {
            append(f.severity.label).append(',')
            append(esc(f.title)).append(',')
            append(esc(f.host)).append(',')
            append(f.port).append(',')
            append(esc(f.category)).append(',')
            appendLine(esc(f.detail))
        }
    }

    fun json(r: AuditResult): String = buildString {
        fun j(s: String?) = "\"" + (s ?: "").replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r") + "\""
        append("{")
        append("\"ssid\":").append(j(r.ssid)).append(",")
        append("\"localIp\":").append(j(r.localIp)).append(",")
        append("\"gateway\":").append(j(r.gateway)).append(",")
        append("\"range\":").append(j("${r.rangeFrom}-${r.rangeTo}")).append(",")
        append("\"startedAt\":").append(r.startedAt).append(",")
        append("\"finishedAt\":").append(r.finishedAt).append(",")
        append("\"findings\":[")
        r.findings.forEachIndexed { i, f ->
            if (i > 0) append(",")
            append("{\"severity\":").append(j(f.severity.name)).append(",")
            append("\"title\":").append(j(f.title)).append(",")
            append("\"host\":").append(j(f.host)).append(",")
            append("\"port\":").append(f.port).append(",")
            append("\"category\":").append(j(f.category)).append(",")
            append("\"detail\":").append(j(f.detail)).append("}")
        }
        append("],\"hosts\":[")
        r.hosts.forEachIndexed { i, ha ->
            if (i > 0) append(",")
            append("{\"ip\":").append(j(ha.host.ip)).append(",")
            append("\"hostname\":").append(j(ha.host.hostname)).append(",")
            append("\"mac\":").append(j(ha.host.mac)).append(",")
            append("\"vendor\":").append(j(ha.host.vendor)).append(",")
            append("\"gateway\":").append(ha.host.isGateway).append(",")
            append("\"openPorts\":[")
            ha.openPorts.forEachIndexed { k, op ->
                if (k > 0) append(",")
                append("{\"port\":").append(op.port).append(",")
                append("\"service\":").append(j(op.service)).append(",")
                append("\"insecure\":").append(op.insecure).append(",")
                append("\"info\":").append(j(op.info)).append("}")
            }
            append("]}")
        }
        append("]}")
    }
}
