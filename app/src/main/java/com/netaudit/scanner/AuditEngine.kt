package com.netaudit.scanner

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import kotlin.coroutines.coroutineContext

/**
 * One-button full network audit: discovery -> service discovery -> port scan ->
 * security probes -> findings. Runs on IO; cancel the enclosing coroutine to stop.
 */
object AuditEngine {

    interface Callbacks {
        suspend fun log(msg: String)
        suspend fun progress(done: Int, total: Int, phase: String)
        suspend fun finding(f: Finding)
        suspend fun updated(result: AuditResult)
    }

    suspend fun run(context: Context, cb: Callbacks): AuditResult? = withContext(Dispatchers.IO) {
        OuiLookup.ensureLoaded(context)
        val net = NetworkUtils.currentWifiNet(context) ?: run {
            cb.log("Kein WLAN verbunden."); return@withContext null
        }
        val range = NetworkUtils.hostRange(net)
        val result = AuditResult(
            ssid = net.ssid,
            localIp = "${net.ipv4.hostAddress}/${net.prefix}",
            gateway = net.gateway,
            rangeFrom = NetworkUtils.intToIp(range.first),
            rangeTo = NetworkUtils.intToIp(range.last),
            startedAt = System.currentTimeMillis()
        )

        // Phase 1: host discovery
        cb.progress(0, 1, "Host-Discovery")
        cb.log("Suche aktive Hosts (${result.rangeFrom}–${result.rangeTo}) …")
        NetworkUtils.discoverHosts(net,
            onHost = { h ->
                synchronized(result) { result.hosts.add(HostAudit(h)) }
                cb.log("Host: ${h.ip}${h.vendor?.let { "  ($it)" } ?: ""}")
                cb.updated(result)
            },
            onProgress = { d, t -> cb.progress(d, t, "Host-Discovery") }
        )
        if (!coroutineContext.isActive) return@withContext finalize(result, cb)
        result.hosts.sortBy { it.host.ipInt }
        cb.log("${result.hosts.size} Hosts gefunden.")

        // Phase 2: service discovery (mDNS/SSDP)
        cb.log("Dienst-Erkennung (mDNS/SSDP) …")
        try {
            ServiceDiscovery.discover(context, 7000,
                onFound = { d ->
                    synchronized(result) { result.services.add(d) }
                    cb.updated(result)
                },
                onStatus = { s -> cb.log(s) }
            )
        } catch (_: Exception) {}
        if (!coroutineContext.isActive) return@withContext finalize(result, cb)

        // Phase 3: per-host port scan + probes
        val hostsCopy = synchronized(result) { result.hosts.toList() }
        hostsCopy.forEachIndexed { idx, ha ->
            if (!coroutineContext.isActive) return@forEachIndexed
            cb.progress(idx, hostsCopy.size, "Port-Scan ${ha.host.ip}")
            cb.log("Port-Scan ${ha.host.ip} …")

            // SNMP default-community check (UDP)
            SecurityProbes.snmpPublicCheck(ha.host.ip)?.let { addFinding(result, it, cb) }

            // UDP service probes (DNS/NTP/NetBIOS)
            val udp = UdpScanner.scan(ha.host.ip)
            if (udp.labels.isNotEmpty()) {
                synchronized(result) { ha.udpPorts.addAll(udp.labels) }
                cb.log("  UDP ${ha.host.ip}: ${udp.labels.joinToString(", ")}")
            }
            for (uf in udp.findings) addFinding(result, uf, cb)

            PortScanner.scan(ha.host.ip, PortScanner.COMMON_PORTS.toList(),
                onOpen = { op ->
                    synchronized(result) { ha.openPorts.add(op) }
                    cb.log("  offen: ${ha.host.ip}:${op.port} (${op.service})")
                    val probeFindings = SecurityProbes.probePort(op, ha.host.ip)
                    for (pf in probeFindings) addFinding(result, pf, cb)
                    synchronized(result) { ha.openPorts.sortBy { it.port } }
                    cb.updated(result)
                },
                onProgress = { _, _ -> }
            )
            // gateway exposure note
            if (ha.host.isGateway && ha.openPorts.any { it.port in intArrayOf(80, 8080, 443) }) {
                addFinding(result, Finding(Severity.INFO, "Router-Weboberfläche erreichbar",
                    ha.host.ip, 0, "Gateway bietet eine Web-Oberfläche. Starkes Passwort und aktuelle Firmware sicherstellen.", "Information"), cb)
            }
        }

        finalize(result, cb)
    }

    private suspend fun addFinding(result: AuditResult, f: Finding, cb: Callbacks) {
        synchronized(result) { result.findings.add(f) }
        cb.finding(f)
    }

    private suspend fun finalize(result: AuditResult, cb: Callbacks): AuditResult {
        synchronized(result) {
            result.findings.sortWith(compareBy({ it.severity.ordinal }, { it.host }, { it.port }))
            result.finishedAt = System.currentTimeMillis()
        }
        cb.log("Audit abgeschlossen: ${result.hosts.size} Hosts, ${result.openPortCount()} offene Ports, ${result.findings.size} Findings.")
        cb.updated(result)
        return result
    }
}
