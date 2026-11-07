package com.netaudit.scanner

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * In-app self-update via a manifest committed to the repository and served by
 * raw.githubusercontent.com (no GitHub Release / token / CI secret needed). The
 * app reads "latest.json" on the update branch, compares its version to the
 * installed one and, if newer, downloads the referenced APK and hands it to the
 * system installer.
 *
 * Manifest (latest.json) format:
 *   { "versionCode": 2, "versionName": "1.1", "notes": "…", "apk": "netaudit-v2.apk" }
 *
 * The repository must be public so the check and download work without a token.
 * Updates must be signed with the SAME keystore as the installed app, otherwise
 * Android refuses to install them.
 */
object UpdateManager {

    data class UpdateInfo(
        val versionCode: Int,
        val versionName: String,
        val notes: String,
        val apkUrl: String,
        val apkName: String
    )

    private fun rawBase() =
        "https://raw.githubusercontent.com/${BuildConfig.GITHUB_OWNER}/" +
            "${BuildConfig.GITHUB_REPO}/${BuildConfig.UPDATE_BRANCH}"

    /** Returns update info only if the manifest advertises a strictly newer build. */
    suspend fun check(): UpdateInfo? = withContext(Dispatchers.IO) {
        val url = "${rawBase()}/latest.json?nocache=${System.currentTimeMillis()}"
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            setRequestProperty("User-Agent", "NetAudit-Updater")
            setRequestProperty("Cache-Control", "no-cache")
            connectTimeout = 10000; readTimeout = 10000
            instanceFollowRedirects = true
        }
        try {
            if (conn.responseCode != 200) return@withContext null
            val json = conn.inputStream.bufferedReader().use { it.readText() }
            val o = JSONObject(json)
            val latestCode = o.optInt("versionCode", -1)
            if (latestCode < 0) return@withContext null
            val name = o.optString("versionName", "v$latestCode")
            val notes = o.optString("notes", "").ifBlank { "Keine Änderungshinweise." }
            val apk = o.optString("apk", "")
            if (apk.isBlank()) return@withContext null
            if (latestCode <= BuildConfig.VERSION_CODE) return@withContext null
            UpdateInfo(latestCode, name, notes, "${rawBase()}/$apk", apk)
        } catch (_: Exception) {
            null
        } finally {
            conn.disconnect()
        }
    }

    /** Downloads the APK to cache, reporting 0..100 progress (or -1 if size unknown). */
    suspend fun download(context: Context, info: UpdateInfo, onProgress: suspend (Int) -> Unit): File =
        withContext(Dispatchers.IO) {
            val dir = File(context.cacheDir, "updates").apply { mkdirs() }
            dir.listFiles()?.forEach { it.delete() }
            val out = File(dir, "netaudit-${info.versionCode}.apk")
            val conn = (URL(info.apkUrl).openConnection() as HttpURLConnection).apply {
                setRequestProperty("User-Agent", "NetAudit-Updater")
                instanceFollowRedirects = true
                connectTimeout = 15000; readTimeout = 30000
            }
            try {
                conn.inputStream.use { input ->
                    out.outputStream().use { file ->
                        val total = conn.contentLength.toLong()
                        val buf = ByteArray(16384)
                        var read = 0L; var n: Int
                        var lastPct = -1
                        while (input.read(buf).also { n = it } > 0) {
                            file.write(buf, 0, n); read += n
                            if (total > 0) {
                                val pct = (read * 100 / total).toInt()
                                if (pct != lastPct) { lastPct = pct; onProgress(pct) }
                            } else onProgress(-1)
                        }
                    }
                }
            } finally {
                conn.disconnect()
            }
            out
        }

    fun canInstall(context: Context): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            context.packageManager.canRequestPackageInstalls() else true

    fun openInstallPermission(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startActivity(
                Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        }
    }

    fun install(context: Context, apk: File) {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", apk)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
    }

    fun currentVersion(): String = "${BuildConfig.VERSION_NAME} (v${BuildConfig.VERSION_CODE})"
}
