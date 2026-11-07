package com.netaudit.scanner

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.netaudit.scanner.databinding.ItemFindingBinding

class FindingsAdapter : RecyclerView.Adapter<FindingsAdapter.VH>() {

    private val items = ArrayList<Finding>()

    fun add(f: Finding) {
        var idx = items.indexOfFirst { it.severity.ordinal > f.severity.ordinal }
        if (idx < 0) idx = items.size
        items.add(idx, f)
        notifyItemInserted(idx)
    }

    fun clear() {
        val n = items.size; items.clear(); notifyItemRangeRemoved(0, n)
    }

    inner class VH(val b: ItemFindingBinding) : RecyclerView.ViewHolder(b.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val b = ItemFindingBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return VH(b)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val f = items[position]
        holder.b.sevChip.text = f.severity.label
        holder.b.sevChip.setBackgroundColor(f.severity.color)
        holder.b.findTitle.text = f.title
        holder.b.findHost.text = if (f.port == 0) f.host else "${f.host}:${f.port}"
        holder.b.findDetail.text = f.detail
    }

    override fun getItemCount() = items.size
}
