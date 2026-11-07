package com.netaudit.scanner

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.netaudit.scanner.databinding.ItemHostBinding

class HostAdapter(
    private val onClick: (Host) -> Unit
) : RecyclerView.Adapter<HostAdapter.VH>() {

    private val items = ArrayList<Host>()

    fun add(host: Host) {
        val idx = items.indexOfFirst { it.ipInt > host.ipInt }
        if (idx < 0) {
            items.add(host); notifyItemInserted(items.size - 1)
        } else {
            items.add(idx, host); notifyItemInserted(idx)
        }
    }

    fun clear() {
        val n = items.size
        items.clear()
        notifyItemRangeRemoved(0, n)
    }

    fun count() = items.size

    inner class VH(val b: ItemHostBinding) : RecyclerView.ViewHolder(b.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val b = ItemHostBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return VH(b)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val h = items[position]
        holder.b.hostIp.text = if (h.isGateway) "${h.ip}  (Gateway)" else h.ip
        holder.b.hostName.text = h.hostname ?: ""
        holder.b.hostName.visibility = if (h.hostname.isNullOrBlank()) android.view.View.GONE else android.view.View.VISIBLE
        holder.b.hostMac.text = h.mac ?: ""
        holder.b.hostMac.visibility = if (h.mac.isNullOrBlank()) android.view.View.GONE else android.view.View.VISIBLE
        holder.b.root.setOnClickListener { onClick(h) }
    }

    override fun getItemCount() = items.size
}
