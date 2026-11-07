package com.netaudit.scanner

import android.content.Context
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Offline MAC-vendor lookup backed by assets/oui.txt (24-bit IEEE OUI prefixes,
 * derived from the Wireshark "manuf" registry). Loaded lazily into memory.
 */
object OuiLookup {

    private val table = HashMap<String, String>(45000)
    private val loaded = AtomicBoolean(false)

    fun ensureLoaded(context: Context) {
        if (loaded.get()) return
        synchronized(this) {
            if (loaded.get()) return
            try {
                context.applicationContext.assets.open("oui.txt").bufferedReader().use { r ->
                    r.forEachLine { line ->
                        val tab = line.indexOf('\t')
                        if (tab == 6) {
                            table[line.substring(0, 6)] = line.substring(tab + 1)
                        }
                    }
                }
            } catch (_: Exception) {
            }
            loaded.set(true)
        }
    }

    /** Returns the vendor for a MAC like "B8:27:EB:12:34:56", or null if unknown. */
    fun vendor(mac: String?): String? {
        if (mac == null) return null
        val hex = mac.filter { it != ':' && it != '-' }.uppercase()
        if (hex.length < 6) return null
        return table[hex.substring(0, 6)]
    }
}
