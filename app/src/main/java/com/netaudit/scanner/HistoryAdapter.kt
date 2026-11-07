package com.netaudit.scanner

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.netaudit.scanner.databinding.ItemHistoryBinding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class HistoryAdapter(
    private val onClick: (HistoryEntry) -> Unit
) : RecyclerView.Adapter<HistoryAdapter.VH>() {

    private val items = ArrayList<HistoryEntry>()
    private val fmt = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.GERMANY)

    fun submit(list: List<HistoryEntry>) {
        items.clear(); items.addAll(list); notifyDataSetChanged()
    }

    inner class VH(val b: ItemHistoryBinding) : RecyclerView.ViewHolder(b.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val b = ItemHistoryBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return VH(b)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val e = items[position]
        holder.b.histTime.text = fmt.format(Date(e.ts))
        holder.b.histSub.text = "${e.ssid ?: "—"}  •  ${e.hostCount} Hosts  •  ${e.findingCount} Findings" +
            if (e.high > 0) "  •  ${e.high}× hoch+" else ""
        holder.b.root.setOnClickListener { onClick(e) }
    }

    override fun getItemCount() = items.size
}
