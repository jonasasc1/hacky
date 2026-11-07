package com.netaudit.scanner

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.netaudit.scanner.databinding.ItemDiscoveryBinding

class DiscoveryAdapter : RecyclerView.Adapter<DiscoveryAdapter.VH>() {

    private val items = ArrayList<Discovered>()

    fun add(d: Discovered) {
        items.add(d)
        notifyItemInserted(items.size - 1)
    }

    fun clear() {
        val n = items.size
        items.clear()
        notifyItemRangeRemoved(0, n)
    }

    fun count() = items.size

    inner class VH(val b: ItemDiscoveryBinding) : RecyclerView.ViewHolder(b.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val b = ItemDiscoveryBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return VH(b)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val d = items[position]
        holder.b.discSource.text = d.source
        holder.b.discTitle.text = d.title
        holder.b.discSub.text = listOfNotNull(d.ip, d.subtitle)
            .joinToString("  •  ")
        holder.b.discSub.visibility = if (holder.b.discSub.text.isBlank()) View.GONE else View.VISIBLE
    }

    override fun getItemCount() = items.size
}
