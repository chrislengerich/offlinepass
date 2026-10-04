package com.linuxpass.app

import android.os.Bundle
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
