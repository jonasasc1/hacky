package com.netaudit.scanner

import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.card.MaterialCardView
import com.netaudit.scanner.databinding.ActivityHttpDetailBinding
import com.netaudit.scanner.vpn.HttpCaptureStore

/** Shows the readable plaintext of one unencrypted HTTP exchange + what an attacker could harvest. */
class HttpDetailActivity : AppCompatActivity() {

    private lateinit var binding: ActivityHttpDetailBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityHttpDetailBinding.inflate(layoutInflater)
        setContentView(binding.root)
        title = getString(R.string.readable_content)

        val id = intent.getStringExtra(EXTRA_ID)
        val cap = HttpCaptureStore.get(id)
        if (cap == null) {
            binding.header.text = getString(R.string.capture_gone)
            return
        }

        binding.header.text = "${cap.method ?: "?"} ${cap.path ?: ""}\n${cap.host}:${cap.port}"

        val hits = cap.sensitive()
        if (hits.isEmpty()) {
            binding.sensitiveCard.visibility = View.GONE
        } else {
            binding.sensitiveList.text = hits.joinToString("\n\n") { "⚠ ${it.label}:\n${it.value}" }
        }

        binding.requestText.text = cap.requestText().ifBlank { "(leer)" }
        binding.responseText.text = cap.responseText().ifBlank { "(noch keine Antwort erfasst)" }
    }

    companion object {
        const val EXTRA_ID = "capture_id"
    }
}
