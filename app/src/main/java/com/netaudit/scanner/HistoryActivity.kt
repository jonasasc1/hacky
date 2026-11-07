package com.netaudit.scanner

import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.DividerItemDecoration
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.netaudit.scanner.databinding.ActivityHistoryBinding

class HistoryActivity : AppCompatActivity() {

    private lateinit var binding: ActivityHistoryBinding
    private lateinit var adapter: HistoryAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityHistoryBinding.inflate(layoutInflater)
        setContentView(binding.root)
        title = getString(R.string.history)

        adapter = HistoryAdapter { entry -> showEntry(entry) }
        binding.histList.layoutManager = LinearLayoutManager(this)
        binding.histList.adapter = adapter
        binding.histList.addItemDecoration(DividerItemDecoration(this, DividerItemDecoration.VERTICAL))
    }

    override fun onResume() {
        super.onResume()
        val entries = HistoryStore.list(this)
        adapter.submit(entries)
        binding.histEmpty.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun showEntry(entry: HistoryEntry) {
        val snap = HistoryStore.load(entry.file)
        val msg = if (snap == null || snap.findingLabels.isEmpty()) {
            "Keine Findings in diesem Scan."
        } else {
            snap.findingLabels.values.sorted().joinToString("\n")
        }
        MaterialAlertDialogBuilder(this)
            .setTitle("Scan ${entry.hostCount} Hosts")
            .setMessage(msg)
            .setPositiveButton("OK", null)
            .show()
    }
}
