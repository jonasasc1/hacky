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
 * In-app self-update via GitHub Releases. The app queries the latest release of
 * the configured repository, compares its version to the installed one and, if
 * newer, downloads the attached APK and hands it to the system installer.
 *
 * Convention: each release is tagged "v<versionCode>" (v1, v2, …) and has the
 * release APK attached as an asset. The repository must be public so the check
 * and download work without a token. Updates must be signed with the SAME
 * keystore as the installed app, otherwise Android refuses to install them.
 */
object UpdateManager {

    data class UpdateInfo(
        val versionCode: Int,
        val versionName: String,
        val notes: String,
        val apkUrl: String,
        val apkName: String
    )

    private fun api() =
        "https://api.github.com/repos/${BuildConfig.GITHUB_OWNER}/${BuildConfig.GITHUB_REPO}/releases/latest"

    /** Returns update info only if a strictly newer release with an APK exists. */
    suspend fun check(): UpdateInfo? = withContext(Dispatchers.IO) {
        val conn = (URL(api()).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            setRequestProperty("Accept", "application/vnd.github+json")
            setRequestProperty("User-Agent", "NetAudit-Updater")
            connectTimeout = 10000; readTimeout = 10000
            instanceFollowRedirects = true
        }
        try {
            if (conn.responseCode != 200) return@withContext null
            val json = conn.inputStream.bufferedReader().use { it.readText() }
            val o = JSONObject(json)
            val tag = o.optString("tag_name", "")
            val latestCode = Regex("(\\d+)").find(tag)?.groupValues?.get(1)?.toIntOrNull()
                ?: return@withContext null
            val notes = o.optString("body", "").ifBlank { "Keine Änderungshinweise." }
            val name = o.optString("name", tag)
            val assets = o.optJSONArray("assets") ?: return@withContext null
            var apkUrl: String? = null; var apkName: String? = null
            for (i in 0 until assets.length()) {
                val a = assets.getJSONObject(i)
                val an = a.optString("name", "")
                if (an.endsWith(".apk", true)) {
                    apkUrl = a.optString("browser_download_url", ""); apkName = an; break
                }
            }
            if (apkUrl.isNullOrBlank()) return@withContext null
            if (latestCode <= BuildConfig.VERSION_CODE) return@withContext null
            UpdateInfo(latestCode, name, notes, apkUrl, apkName ?: "netaudit-update.apk")
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
