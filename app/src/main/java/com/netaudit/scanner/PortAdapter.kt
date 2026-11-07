package com.netaudit.scanner

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.netaudit.scanner.databinding.ItemPortBinding

class PortAdapter : RecyclerView.Adapter<PortAdapter.VH>() {

    private val items = ArrayList<OpenPort>()

    fun add(p: OpenPort) {
        val idx = items.indexOfFirst { it.port > p.port }
        if (idx < 0) {
            items.add(p); notifyItemInserted(items.size - 1)
        } else {
            items.add(idx, p); notifyItemInserted(idx)
        }
    }

    fun clear() {
        val n = items.size
        items.clear()
        notifyItemRangeRemoved(0, n)
    }

    fun count() = items.size

    inner class VH(val b: ItemPortBinding) : RecyclerView.ViewHolder(b.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val b = ItemPortBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return VH(b)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val p = items[position]
        holder.b.portLine.text = "%5d/tcp  %s".format(p.port, p.service)
        holder.b.portBanner.text = p.banner ?: ""
        holder.b.portBanner.visibility = if (p.banner.isNullOrBlank()) View.GONE else View.VISIBLE
    }

    override fun getItemCount() = items.size
}
