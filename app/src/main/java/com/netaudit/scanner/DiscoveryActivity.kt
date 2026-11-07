package com.netaudit.scanner

import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.DividerItemDecoration
import androidx.recyclerview.widget.LinearLayoutManager
import com.netaudit.scanner.databinding.ActivityDiscoveryBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DiscoveryActivity : AppCompatActivity() {

    private lateinit var binding: ActivityDiscoveryBinding
    private lateinit var adapter: DiscoveryAdapter
    private var job: Job? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDiscoveryBinding.inflate(layoutInflater)
        setContentView(binding.root)

        adapter = DiscoveryAdapter()
        binding.discList.layoutManager = LinearLayoutManager(this)
        binding.discList.adapter = adapter
        binding.discList.addItemDecoration(
            DividerItemDecoration(this, DividerItemDecoration.VERTICAL)
        )

        binding.discStart.setOnClickListener { start() }
        binding.discStop.setOnClickListener { stop() }
    }

    private fun start() {
        adapter.clear()
        setRunning(true)
        job = lifecycleScope.launch(Dispatchers.Default) {
            try {
                ServiceDiscovery.discover(
                    context = applicationContext,
                    durationMs = 8000,
                    onFound = { d -> withContext(Dispatchers.Main) {
                        adapter.add(d)
                        binding.discStatus.text = "${adapter.count()} Dienste/Geräte gefunden"
                    } },
                    onStatus = { s -> withContext(Dispatchers.Main) { binding.discStatus.text = s } }
                )
                withContext(Dispatchers.Main) {
                    binding.discStatus.text = "Fertig  •  ${adapter.count()} Einträge"
                }
            } catch (_: Exception) {
            } finally {
                withContext(Dispatchers.Main) { setRunning(false) }
            }
        }
    }

    private fun stop() {
        job?.cancel()
        setRunning(false)
        binding.discStatus.text = "Abgebrochen  •  ${adapter.count()} Einträge"
    }

    private fun setRunning(active: Boolean) {
        binding.discStart.isEnabled = !active
        binding.discStop.isEnabled = active
        binding.discProgress.visibility = if (active) View.VISIBLE else View.INVISIBLE
    }

    override fun onDestroy() {
        job?.cancel()
        super.onDestroy()
    }
}
