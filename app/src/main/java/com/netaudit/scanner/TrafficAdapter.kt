package com.netaudit.scanner

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.netaudit.scanner.databinding.ItemTrafficBinding
import com.netaudit.scanner.vpn.TrafficEvent
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class TrafficAdapter(
    private val onClick: (TrafficEvent) -> Unit = {}
) : RecyclerView.Adapter<TrafficAdapter.VH>() {

    private val items = ArrayList<TrafficEvent>()
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.GERMANY)

    fun add(e: TrafficEvent) {
        items.add(0, e)
        if (items.size > 500) items.removeAt(items.size - 1)
        notifyItemInserted(0)
    }

    fun setAll(list: List<TrafficEvent>) {
        items.clear(); items.addAll(list.asReversed()); notifyDataSetChanged()
    }

    fun clear() { val n = items.size; items.clear(); notifyItemRangeRemoved(0, n) }

    inner class VH(val b: ItemTrafficBinding) : RecyclerView.ViewHolder(b.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val b = ItemTrafficBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return VH(b)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val e = items[position]
        holder.b.kind.text = e.kind
        holder.b.kind.setBackgroundColor(if (e.insecure) 0xFFD32F2F.toInt() else 0xFF455A64.toInt())
        holder.b.target.text = e.domain ?: "${e.dstIp}:${e.port}"
        holder.b.sub.text = listOfNotNull(
            fmt.format(Date(e.time)),
            if (e.domain != null) "${e.dstIp}:${e.port}" else null,
            e.detail,
            if (e.captureId != null) "⇢ Inhalt ansehen" else null
        ).joinToString("  •  ")
        holder.b.root.setOnClickListener { if (e.captureId != null) onClick(e) }
        holder.b.root.isClickable = e.captureId != null
    }

    override fun getItemCount() = items.size
}
