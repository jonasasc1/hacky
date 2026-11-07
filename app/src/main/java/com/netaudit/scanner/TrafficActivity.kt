package com.netaudit.scanner

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.netaudit.scanner.databinding.ActivityTrafficBinding
import com.netaudit.scanner.vpn.TrafficEvent
import com.netaudit.scanner.vpn.TrafficLog
import com.netaudit.scanner.vpn.TrafficMonitorService

class TrafficActivity : AppCompatActivity(), TrafficLog.Listener {

    private lateinit var binding: ActivityTrafficBinding
    private lateinit var adapter: TrafficAdapter

    private val vpnPrepare = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res -> if (res.resultCode == RESULT_OK) startVpn() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityTrafficBinding.inflate(layoutInflater)
        setContentView(binding.root)
        title = getString(R.string.traffic_title)

        adapter = TrafficAdapter { e ->
            startActivity(
                android.content.Intent(this, HttpDetailActivity::class.java)
                    .putExtra(HttpDetailActivity.EXTRA_ID, e.captureId)
            )
        }
        binding.trafficList.layoutManager = LinearLayoutManager(this)
        binding.trafficList.adapter = adapter

        binding.trafficToggle.setOnClickListener {
            if (TrafficLog.running) stopVpn() else requestStart()
        }
        binding.trafficClear.setOnClickListener { TrafficLog.clear(); adapter.clear(); refreshStatus() }
    }

    override fun onResume() {
        super.onResume()
        adapter.setAll(TrafficLog.snapshot())
        TrafficLog.setListener(this)
        refreshStatus()
    }

    override fun onPause() {
        TrafficLog.setListener(null)
        super.onPause()
    }

    private fun requestStart() {
        val prep = VpnService.prepare(this)
        if (prep != null) vpnPrepare.launch(prep) else startVpn()
    }

    private fun startVpn() {
        startService(Intent(this, TrafficMonitorService::class.java))
        binding.trafficToggle.postDelayed({ refreshStatus() }, 400)
    }

    private fun stopVpn() {
        startService(Intent(this, TrafficMonitorService::class.java).setAction(TrafficMonitorService.ACTION_STOP))
        binding.trafficToggle.postDelayed({ refreshStatus() }, 400)
    }

    private fun refreshStatus() {
        val on = TrafficLog.running
        binding.trafficToggle.text = getString(if (on) R.string.traffic_stop else R.string.traffic_start)
        binding.trafficStatus.text = if (on)
            "Mitschnitt aktiv  •  ${TrafficLog.plaintextCount} Klartext-Verbindungen erkannt"
        else "Gestoppt. Startet einen lokalen VPN (nur dieses Gerät)."
    }

    override fun onEvent(e: TrafficEvent) {
        runOnUiThread { adapter.add(e); refreshStatus() }
    }
}
