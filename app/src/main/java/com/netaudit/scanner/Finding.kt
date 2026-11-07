package com.netaudit.scanner

enum class Severity(val label: String, val color: Int) {
    CRITICAL("KRITISCH", 0xFFD32F2F.toInt()),
    HIGH("HOCH", 0xFFF4511E.toInt()),
    MEDIUM("MITTEL", 0xFFF9A825.toInt()),
    LOW("NIEDRIG", 0xFF1E88E5.toInt()),
    INFO("INFO", 0xFF757575.toInt())
}

data class Finding(
    val severity: Severity,
    val title: String,
    val host: String,
    val port: Int,           // 0 = host-level
    val detail: String,
    val category: String
)

/** One host with the TCP ports found open on it. */
data class HostAudit(
    val host: Host,
    val openPorts: MutableList<OpenPort> = ArrayList()
)

data class AuditResult(
    val ssid: String?,
    val localIp: String,
    val gateway: String?,
    val rangeFrom: String,
    val rangeTo: String,
    val hosts: MutableList<HostAudit> = ArrayList(),
    val services: MutableList<Discovered> = ArrayList(),
    val findings: MutableList<Finding> = ArrayList(),
    var startedAt: Long = 0,
    var finishedAt: Long = 0
) {
    fun countBy(sev: Severity) = findings.count { it.severity == sev }
    fun openPortCount() = hosts.sumOf { it.openPorts.size }
}
