package com.netaudit.scanner

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.netaudit.scanner.databinding.ActivityUpdateBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class UpdateActivity : AppCompatActivity() {

    private lateinit var binding: ActivityUpdateBinding
    private var pending: UpdateManager.UpdateInfo? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityUpdateBinding.inflate(layoutInflater)
        setContentView(binding.root)
        title = getString(R.string.update_title)

        binding.currentVersion.text = getString(R.string.current_version, UpdateManager.currentVersion())
        binding.checkUpdate.setOnClickListener { check() }
        binding.installUpdate.setOnClickListener { installFlow() }
        binding.installUpdate.visibility = View.GONE
    }

    override fun onResume() {
        super.onResume()
        // returning from the "install unknown apps" settings screen
        if (pending != null && UpdateManager.canInstall(this)) {
            binding.updateStatus.text = getString(R.string.update_ready)
        }
    }

    private fun check() {
        binding.checkUpdate.isEnabled = false
        binding.updateStatus.text = getString(R.string.update_checking)
        binding.installUpdate.visibility = View.GONE
        lifecycleScope.launch {
            val info = try { UpdateManager.check() } catch (_: Exception) { null }
            binding.checkUpdate.isEnabled = true
            if (info == null) {
                binding.updateStatus.text = getString(R.string.update_none)
                binding.changelog.text = ""
                return@launch
            }
            pending = info
            binding.updateStatus.text = getString(R.string.update_available, info.versionName)
            binding.changelog.text = info.notes
            binding.installUpdate.visibility = View.VISIBLE
        }
    }

    private fun installFlow() {
        val info = pending ?: return
        if (!UpdateManager.canInstall(this)) {
            Toast.makeText(this, R.string.update_need_permission, Toast.LENGTH_LONG).show()
            UpdateManager.openInstallPermission(this)
            return
        }
        binding.installUpdate.isEnabled = false
        binding.updateProgress.visibility = View.VISIBLE
        binding.updateStatus.text = getString(R.string.update_downloading)
        lifecycleScope.launch {
            try {
                val file = UpdateManager.download(applicationContext, info) { pct ->
                    withContext(Dispatchers.Main) {
                        if (pct >= 0) {
                            binding.updateProgress.isIndeterminate = false
                            binding.updateProgress.progress = pct
                        } else binding.updateProgress.isIndeterminate = true
                    }
                }
                binding.updateProgress.visibility = View.GONE
                binding.updateStatus.text = getString(R.string.update_installing)
                UpdateManager.install(applicationContext, file)
            } catch (_: Exception) {
                binding.updateProgress.visibility = View.GONE
                binding.updateStatus.text = getString(R.string.update_failed)
            } finally {
                binding.installUpdate.isEnabled = true
            }
        }
    }
}
