package com.netaudit.scanner

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.DividerItemDecoration
import androidx.recyclerview.widget.LinearLayoutManager
import com.netaudit.scanner.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var adapter: HostAdapter
    private var scanJob: Job? = null

    private val locationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { showNetworkInfo() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        adapter = HostAdapter { host ->
            startActivity(Intent(this, PortScanActivity::class.java).apply {
                putExtra(PortScanActivity.EXTRA_IP, host.ip)
            })
        }
        binding.hostList.layoutManager = LinearLayoutManager(this)
        binding.hostList.adapter = adapter
        binding.hostList.addItemDecoration(
            DividerItemDecoration(this, DividerItemDecoration.VERTICAL)
        )

        binding.scanButton.setOnClickListener { startScan() }
        binding.stopButton.setOnClickListener { stopScan() }

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
            != PackageManager.PERMISSION_GRANTED
        ) {
            locationPermission.launch(Manifest.permission.ACCESS_FINE_LOCATION)
        } else {
            showNetworkInfo()
        }
    }

    private fun showNetworkInfo() {
        val net = NetworkUtils.currentWifiNet(this)
        if (net == null) {
            binding.networkInfo.text = getString(R.string.no_network)
            binding.scanButton.isEnabled = false
            return
        }
        binding.scanButton.isEnabled = true
        val range = NetworkUtils.hostRange(net)
        binding.networkInfo.text = buildString {
            appendLine("SSID     : ${net.ssid ?: "(Berechtigung/—)"}")
            appendLine("IP       : ${net.ipv4.hostAddress}/${net.prefix}")
            appendLine("Gateway  : ${net.gateway ?: "—"}")
            append("Scan-Range: ${NetworkUtils.intToIp(range.first)} – ${NetworkUtils.intToIp(range.last)} (${range.count()} Hosts)")
        }
    }

    private fun startScan() {
        val net = NetworkUtils.currentWifiNet(this) ?: return
        adapter.clear()
        setScanning(true)
        scanJob = lifecycleScope.launch(Dispatchers.Default) {
            try {
                NetworkUtils.discoverHosts(
                    net = net,
                    onHost = { host ->
                        withContext(Dispatchers.Main) { adapter.add(host) }
                    },
                    onProgress = { done, total ->
                        withContext(Dispatchers.Main) {
                            binding.progress.max = total
                            binding.progress.progress = done
                            binding.statusLine.text =
                                "Scanne… $done/$total  •  ${adapter.count()} Hosts gefunden"
                        }
                    }
                )
                withContext(Dispatchers.Main) {
                    binding.statusLine.text = "Fertig  •  ${adapter.count()} Hosts gefunden"
                }
            } catch (_: Exception) {
            } finally {
                withContext(Dispatchers.Main) { setScanning(false) }
            }
        }
    }

    private fun stopScan() {
        scanJob?.cancel()
        setScanning(false)
        binding.statusLine.text = "Abgebrochen  •  ${adapter.count()} Hosts gefunden"
    }

    private fun setScanning(active: Boolean) {
        binding.scanButton.isEnabled = !active
        binding.stopButton.isEnabled = active
        binding.progress.visibility = if (active) View.VISIBLE else View.INVISIBLE
    }

    override fun onDestroy() {
        scanJob?.cancel()
        super.onDestroy()
    }
}
