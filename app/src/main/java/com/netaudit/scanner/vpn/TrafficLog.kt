package com.netaudit.scanner.vpn

import java.util.concurrent.ConcurrentHashMap

data class TrafficEvent(
    val time: Long,
    val proto: String,          // TCP / UDP / DNS
    val dstIp: String,
    val port: Int,
    val domain: String?,
    val kind: String,           // "HTTP (Klartext)", "TLS", "DNS", "andere"
    val detail: String?,
    val insecure: Boolean,
    val captureId: String? = null   // set for cleartext HTTP: opens readable content
)

/** Process-wide sink for traffic events produced by the VPN service. */
object TrafficLog {

    private const val MAX = 500
    private val events = ArrayList<TrafficEvent>()
    private val dnsCache = ConcurrentHashMap<String, String>()   // ip -> domain
    @Volatile var running = false
    @Volatile var plaintextCount = 0
        private set

    interface Listener { fun onEvent(e: TrafficEvent) }
    @Volatile private var listener: Listener? = null

    fun setListener(l: Listener?) { listener = l }

    fun rememberDns(domain: String, ip: String) { dnsCache[ip] = domain }
    fun domainFor(ip: String): String? = dnsCache[ip]

    @Synchronized
    fun add(e: TrafficEvent) {
        events.add(e)
        if (events.size > MAX) events.removeAt(0)
        if (e.insecure) plaintextCount++
        listener?.onEvent(e)
    }

    @Synchronized fun snapshot(): List<TrafficEvent> = ArrayList(events)

    @Synchronized fun clear() { events.clear(); plaintextCount = 0; HttpCaptureStore.clear() }
}
