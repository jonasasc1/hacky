package com.netaudit.scanner

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.DividerItemDecoration
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.netaudit.scanner.databinding.ActivityAuditBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AuditActivity : AppCompatActivity(), AuditEngine.Callbacks {

    private lateinit var binding: ActivityAuditBinding
    private lateinit var adapter: FindingsAdapter
    private var job: Job? = null
    private var result: AuditResult? = null
    private var pendingExport: ByteArray? = null
    private var pendingExt = "html"

    private val createDoc = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val data = pendingExport; pendingExport = null
        if (uri == null || data == null) return@registerForActivityResult
        try {
            contentResolver.openOutputStream(uri)?.use { it.write(data) }
            toast(getString(R.string.exported))
        } catch (_: Exception) { toast(getString(R.string.export_failed)) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAuditBinding.inflate(layoutInflater)
        setContentView(binding.root)
        title = getString(R.string.full_audit)

        adapter = FindingsAdapter()
        binding.findingList.layoutManager = LinearLayoutManager(this)
        binding.findingList.adapter = adapter
        binding.findingList.addItemDecoration(DividerItemDecoration(this, DividerItemDecoration.VERTICAL))

        binding.startAudit.setOnClickListener { startAudit() }
        binding.stopAudit.setOnClickListener { stopAudit() }
        binding.reportAudit.setOnClickListener { exportReport() }

        startAudit()
    }

    private fun startAudit() {
        adapter.clear()
        result = null
        setRunning(true)
        binding.summary.text = "Audit läuft …"
        job = lifecycleScope.launch(Dispatchers.Default) {
            try {
                result = AuditEngine.run(applicationContext, this@AuditActivity)
            } catch (_: Exception) {
            } finally {
                withContext(Dispatchers.Main) { setRunning(false) }
            }
        }
    }

    private fun stopAudit() {
        job?.cancel()
        setRunning(false)
        binding.auditStatus.text = "Abgebrochen."
    }

    private fun setRunning(active: Boolean) {
        binding.startAudit.isEnabled = !active
        binding.stopAudit.isEnabled = active
        binding.auditProgress.visibility = if (active) View.VISIBLE else View.INVISIBLE
    }

    private fun exportReport() {
        val r = result
        if (r == null || r.finishedAt == 0L) { toast(getString(R.string.nothing_to_export)); return }
        val ts = System.currentTimeMillis()
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.report_format)
            .setItems(arrayOf("HTML (Report)", "CSV", "JSON")) { _, which ->
                when (which) {
                    0 -> { pendingExport = ReportBuilder.html(r).toByteArray(); createDoc.launch("netaudit-report-$ts.html") }
                    1 -> { pendingExport = ReportBuilder.csv(r).toByteArray(); createDoc.launch("netaudit-findings-$ts.csv") }
                    2 -> { pendingExport = ReportBuilder.json(r).toByteArray(); createDoc.launch("netaudit-audit-$ts.json") }
                }
            }
            .show()
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    // ---- AuditEngine.Callbacks (called off main thread) ----
    override suspend fun log(msg: String) = withContext(Dispatchers.Main) {
        binding.auditStatus.text = msg
    }

    override suspend fun progress(done: Int, total: Int, phase: String) = withContext(Dispatchers.Main) {
        binding.auditProgress.isIndeterminate = total <= 1
        if (total > 1) { binding.auditProgress.max = total; binding.auditProgress.progress = done }
        binding.auditStatus.text = "$phase … ($done/$total)"
    }

    override suspend fun finding(f: Finding) = withContext(Dispatchers.Main) {
        adapter.add(f)
    }

    override suspend fun updated(r: AuditResult) = withContext(Dispatchers.Main) {
        binding.summary.text = buildString {
            append("Hosts: ${r.hosts.size}   Offene Ports: ${r.openPortCount()}\n")
            append("KRITISCH ${r.countBy(Severity.CRITICAL)}  •  HOCH ${r.countBy(Severity.HIGH)}  •  ")
            append("MITTEL ${r.countBy(Severity.MEDIUM)}  •  NIEDRIG ${r.countBy(Severity.LOW)}  •  INFO ${r.countBy(Severity.INFO)}")
        }
    }

    override fun onDestroy() {
        job?.cancel()
        super.onDestroy()
    }
}
