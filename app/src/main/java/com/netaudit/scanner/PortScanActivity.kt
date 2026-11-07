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
import com.netaudit.scanner.databinding.ActivityPortscanBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class PortScanActivity : AppCompatActivity() {

    private lateinit var binding: ActivityPortscanBinding
    private lateinit var adapter: PortAdapter
    private var job: Job? = null
    private lateinit var ip: String
    private var pendingExport: ByteArray? = null

    private val createDoc = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val data = pendingExport
        pendingExport = null
        if (uri == null || data == null) return@registerForActivityResult
        try {
            contentResolver.openOutputStream(uri)?.use { it.write(data) }
            toast(getString(R.string.exported))
        } catch (_: Exception) {
            toast(getString(R.string.export_failed))
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityPortscanBinding.inflate(layoutInflater)
        setContentView(binding.root)

        ip = intent.getStringExtra(EXTRA_IP) ?: run { finish(); return }
        binding.targetTitle.text = "Ziel: $ip"

        adapter = PortAdapter()
        binding.portList.layoutManager = LinearLayoutManager(this)
        binding.portList.adapter = adapter
        binding.portList.addItemDecoration(
            DividerItemDecoration(this, DividerItemDecoration.VERTICAL)
        )

        binding.modeGroup.check(binding.modeCommon.id)
        binding.modeGroup.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (isChecked) {
                binding.rangeRow.visibility =
                    if (checkedId == binding.modeRange.id) View.VISIBLE else View.GONE
            }
        }

        binding.startScan.setOnClickListener { startScan() }
        binding.stopScan.setOnClickListener { stopScan() }
        binding.exportPorts.setOnClickListener { exportPorts() }
    }

    private fun exportPorts() {
        val ports = adapter.snapshot()
        if (ports.isEmpty()) {
            toast(getString(R.string.nothing_to_export)); return
        }
        val ts = System.currentTimeMillis()
        val safeIp = ip.replace('.', '-')
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.export_choose)
            .setItems(arrayOf("CSV", "JSON")) { _, which ->
                if (which == 0) {
                    pendingExport = Exporter.portsCsv(ip, ports).toByteArray()
                    createDoc.launch("netaudit-ports-$safeIp-$ts.csv")
                } else {
                    pendingExport = Exporter.portsJson(ip, ports).toByteArray()
                    createDoc.launch("netaudit-ports-$safeIp-$ts.json")
                }
            }
            .show()
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    private fun resolvePorts(): List<Int>? {
        return if (binding.modeGroup.checkedButtonId == binding.modeRange.id) {
            val from = binding.portFrom.text?.toString()?.toIntOrNull()
            val to = binding.portTo.text?.toString()?.toIntOrNull()
            if (from == null || to == null || from < 1 || to > 65535 || from > to) {
                binding.portStatus.text = "Ungültiger Bereich (1–65535, von ≤ bis)."
                return null
            }
            if (to - from > 20000) {
                binding.portStatus.text = "Bereich zu groß (max. 20000 Ports pro Scan)."
                return null
            }
            (from..to).toList()
        } else {
            PortScanner.COMMON_PORTS.toList()
        }
    }

    private fun startScan() {
        val ports = resolvePorts() ?: return
        adapter.clear()
        setScanning(true)
        job = lifecycleScope.launch(Dispatchers.Default) {
            try {
                PortScanner.scan(
                    ip = ip,
                    ports = ports,
                    onOpen = { op -> withContext(Dispatchers.Main) { adapter.add(op) } },
                    onProgress = { done, total ->
                        withContext(Dispatchers.Main) {
                            binding.portProgress.max = total
                            binding.portProgress.progress = done
                            binding.portStatus.text =
                                "Scanne… $done/$total  •  ${adapter.count()} offen"
                        }
                    }
                )
                withContext(Dispatchers.Main) {
                    binding.portStatus.text =
                        "Fertig  •  ${adapter.count()} offene Ports"
                }
            } catch (_: Exception) {
            } finally {
                withContext(Dispatchers.Main) { setScanning(false) }
            }
        }
    }

    private fun stopScan() {
        job?.cancel()
        setScanning(false)
        binding.portStatus.text = "Abgebrochen  •  ${adapter.count()} offen"
    }

    private fun setScanning(active: Boolean) {
        binding.startScan.isEnabled = !active
        binding.stopScan.isEnabled = active
        binding.portProgress.visibility = if (active) View.VISIBLE else View.INVISIBLE
    }

    override fun onDestroy() {
        job?.cancel()
        super.onDestroy()
    }

    companion object {
        const val EXTRA_IP = "extra_ip"
    }
}
