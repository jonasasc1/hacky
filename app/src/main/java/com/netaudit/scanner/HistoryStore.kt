package com.netaudit.scanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Snapshot of a past audit, kept for diffing ("what's new on the network?"). */
data class Snapshot(
    val ts: Long,
    val ssid: String?,
    val tcp: Map<String, Set<Int>>,         // ip -> open tcp ports
    val findingSigs: Set<String>,           // "SEV|title|host|port"
    val findingLabels: Map<String, String>  // sig -> human label
)

data class HistoryEntry(
    val file: File,
    val ts: Long,
    val ssid: String?,
    val hostCount: Int,
    val findingCount: Int,
    val high: Int
)

data class AuditDiff(
    val newHosts: List<String>,
    val goneHosts: List<String>,
    val newPorts: List<String>,     // "ip:port"
    val newFindings: List<String>   // human labels
) {
    fun isEmpty() = newHosts.isEmpty() && goneHosts.isEmpty() &&
        newPorts.isEmpty() && newFindings.isEmpty()
}

object HistoryStore {

    private fun dir(ctx: Context) = File(ctx.filesDir, "history").apply { mkdirs() }

    fun save(ctx: Context, r: AuditResult): File {
        val o = JSONObject()
        o.put("ts", r.finishedAt)
        o.put("ssid", r.ssid ?: JSONObject.NULL)
        val hosts = JSONArray()
        for (ha in r.hosts) {
            val ho = JSONObject()
            ho.put("ip", ha.host.ip)
            ho.put("tcp", JSONArray(ha.openPorts.map { it.port }))
            ho.put("udp", JSONArray(ha.udpPorts))
            hosts.put(ho)
        }
        o.put("hosts", hosts)
        val fs = JSONArray()
        for (f in r.findings) {
            val fo = JSONObject()
            fo.put("s", f.severity.name); fo.put("t", f.title)
            fo.put("h", f.host); fo.put("p", f.port)
            fs.put(fo)
        }
        o.put("findings", fs)
        val file = File(dir(ctx), "audit-${r.finishedAt}.json")
        file.writeText(o.toString())
        // keep last 50
        list(ctx).drop(50).forEach { runCatching { it.file.delete() } }
        return file
    }

    fun list(ctx: Context): List<HistoryEntry> {
        val files = dir(ctx).listFiles { f -> f.name.endsWith(".json") } ?: return emptyList()
        return files.mapNotNull { f ->
            try {
                val o = JSONObject(f.readText())
                val fs = o.getJSONArray("findings")
                var high = 0
                for (i in 0 until fs.length()) {
                    val s = fs.getJSONObject(i).getString("s")
                    if (s == "CRITICAL" || s == "HIGH") high++
                }
                HistoryEntry(
                    f, o.getLong("ts"),
                    o.optString("ssid", null),
                    o.getJSONArray("hosts").length(),
                    fs.length(), high
                )
            } catch (_: Exception) { null }
        }.sortedByDescending { it.ts }
    }

    fun load(file: File): Snapshot? {
        return try {
            val o = JSONObject(file.readText())
            val tcp = HashMap<String, Set<Int>>()
            val hosts = o.getJSONArray("hosts")
            for (i in 0 until hosts.length()) {
                val ho = hosts.getJSONObject(i)
                val ports = HashSet<Int>()
                val arr = ho.getJSONArray("tcp")
                for (k in 0 until arr.length()) ports.add(arr.getInt(k))
                tcp[ho.getString("ip")] = ports
            }
            val sigs = HashSet<String>()
            val labels = HashMap<String, String>()
            val fs = o.getJSONArray("findings")
            for (i in 0 until fs.length()) {
                val fo = fs.getJSONObject(i)
                val sig = "${fo.getString("s")}|${fo.getString("t")}|${fo.getString("h")}|${fo.getInt("p")}"
                sigs.add(sig)
                labels[sig] = "${fo.getString("s")}: ${fo.getString("t")} (${fo.getString("h")}" +
                    (if (fo.getInt("p") != 0) ":${fo.getInt("p")}" else "") + ")"
            }
            Snapshot(o.getLong("ts"), o.optString("ssid", null), tcp, sigs, labels)
        } catch (_: Exception) { null }
    }

    /** Most recent snapshot strictly older than [beforeTs], same SSID preferred. */
    fun previous(ctx: Context, beforeTs: Long, ssid: String?): Snapshot? {
        val candidates = list(ctx).filter { it.ts < beforeTs }
        val entry = candidates.firstOrNull { it.ssid == ssid } ?: candidates.firstOrNull()
        return entry?.let { load(it.file) }
    }

    fun diff(prev: Snapshot?, cur: AuditResult): AuditDiff {
        if (prev == null) return AuditDiff(emptyList(), emptyList(), emptyList(), emptyList())
        val curTcp = cur.hosts.associate { it.host.ip to it.openPorts.map { p -> p.port }.toSet() }
        val newHosts = curTcp.keys - prev.tcp.keys
        val goneHosts = prev.tcp.keys - curTcp.keys
        val newPorts = ArrayList<String>()
        for ((ip, ports) in curTcp) {
            val before = prev.tcp[ip] ?: emptySet()
            for (p in ports - before) newPorts.add("$ip:$p")
        }
        val curSigs = cur.findings.map { "${it.severity.name}|${it.title}|${it.host}|${it.port}" }.toSet()
        val newSigs = curSigs - prev.findingSigs
        val newFindings = cur.findings
            .filter { "${it.severity.name}|${it.title}|${it.host}|${it.port}" in newSigs }
            .map { "${it.severity.label}: ${it.title} (${it.host}${if (it.port != 0) ":${it.port}" else ""})" }
        return AuditDiff(newHosts.sorted(), goneHosts.sorted(), newPorts, newFindings)
    }
}
