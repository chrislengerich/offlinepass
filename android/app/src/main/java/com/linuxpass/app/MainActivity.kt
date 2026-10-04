package com.linuxpass.app

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/** Spike shell: S1 (OpenKeyChain round-trip) wires its UI into the spike package. */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.i("S1", "MainActivity onCreate extras=${intent.extras?.keySet()}")
        // ADB-driven spike entry: forward extras to S1 (kept non-exported).
        val e = intent
        val forward = Intent(this, com.linuxpass.app.spike.S1DecryptActivity::class.java).apply {
            listOf("path", "email", "exportKey", "probeSign").forEach { key ->
                e.getStringExtra(key)?.let { putExtra(key, it) }
            }
        }
        if (forward.hasExtra("path") || forward.hasExtra("email") ||
            forward.hasExtra("exportKey") || forward.hasExtra("probeSign")) {
            startActivity(forward)
            finish()
            return
        }
        setContent {
            Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
                    Text("linuxpass — spike stub")
                    androidx.compose.material3.Button(onClick = {
                        startActivity(android.content.Intent(this@MainActivity, com.linuxpass.app.spike.S1DecryptActivity::class.java))
                    }) {
                        Text("Open Spike S1 (OpenKeyChain round-trip)")
                    }
                }
            }
        }
    }
}
