package com.netaudit.scanner

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.netaudit.scanner.databinding.ActivityConsentBinding

/**
 * First screen. Forces the user to acknowledge that NetAudit may only be used
 * on networks they own or are explicitly authorised to test. The flag is stored
 * so it is only shown once.
 */
class ConsentActivity : AppCompatActivity() {

    private lateinit var binding: ActivityConsentBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (prefs.getBoolean(KEY_CONSENT, false)) {
            goToMain()
            return
        }

        binding = ActivityConsentBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.consentCheck.setOnCheckedChangeListener { _, checked ->
            binding.consentButton.isEnabled = checked
        }
        binding.consentButton.setOnClickListener {
            prefs.edit().putBoolean(KEY_CONSENT, true).apply()
            goToMain()
        }
    }

    private fun goToMain() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }

    companion object {
        const val PREFS = "netaudit"
        const val KEY_CONSENT = "consent_accepted"
    }
}
