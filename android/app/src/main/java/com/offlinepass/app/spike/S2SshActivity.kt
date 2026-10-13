package com.offlinepass.app.spike

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.offlinepass.app.crypto.SshKeyManager
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Spike S2 — per-device git identity: an Android-Keystore SSH key
 * (non-exportable, TEE-held) plus a standalone jsch auth test against
 * git@github.com. Enrollment: the printed OpenSSH line goes into the
 * vault repo as a read/write deploy key.
 */
class S2SshActivity : ComponentActivity() {

    private val status = mutableStateOf("Generate the key first.")

    private fun setStatus(t: String) {
        status.value = t
        Log.i(TAG, t)
    }

    private val mgr = SshKeyManager()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { Screen() }
    }

    private fun ensureKey() {
        lifecycleScope.launch {
            try {
                val info = withContext(Dispatchers.IO) { mgr.ensureKeyPair() }
                val out = File(outDir(), "id-offlinepass.pub")
                out.writeText(info.openSshLine + "\n")
                setStatus("KEY: ${info.algorithm}\n${info.openSshLine}\n-> ${out.absolutePath}")
            } catch (e: Exception) {
                setStatus("KEYGEN FAILED: ${e.javaClass.simpleName}: ${e.message}")
            }
        }
    }

    private fun testAuth(host: String) {
        lifecycleScope.launch {
            // DNS probe first: distinguishes resolver failures from auth ones.
            val dns = runCatching {
                java.net.InetAddress.getByName("github.com").hostAddress
            }.fold({ "resolved=${it}" }, { "DNS FAILED: ${it.message}" })
            setStatus("dns: $dns; connecting to $host:22 (Keystore-signed auth)…")
            val result = withContext(Dispatchers.IO) { runCatching { jschAuthTest(host) } }
            result.fold(
                onSuccess = { setStatus("AUTH OK: $it") },
                onFailure = { setStatus("AUTH FAILED: ${it.javaClass.simpleName}: ${it.message}") }
            )
        }
    }

    /**
     * jsch session connect performs the userauth exchange; a completed
     * connect (plus the session banner) proves GitHub accepted our
     * Keystore-backed signature.
     */
    private fun jschAuthTest(host: String): String {
        val jsch = JSch()
        jsch.addIdentity(object : com.jcraft.jsch.Identity {
            private val info = mgr.ensureKeyPair()
            override fun getAlgName(): String = if (info.algorithm == "Ed25519") "ssh-ed25519" else "ssh-rsa"
            override fun getName(): String = "offlinepass-android"
            override fun getPublicKeyBlob(): ByteArray = info.wireBlob
            override fun getSignature(data: ByteArray): ByteArray {
                val sig = mgr.newSigner()
                sig.update(data)
                val s = sig.sign()
                val blobAlg = if (info.algorithm == "Ed25519") "ssh-ed25519" else "rsa-sha2-256"
                return sshString(blobAlg.toByteArray()) + sshString(s)
            }
            override fun setPassphrase(passphrase: ByteArray?): Boolean = true
            override fun isEncrypted(): Boolean = false
            override fun clear() {}
        }, null)

        val session: Session = jsch.getSession("git", host, 22)
        try {
            session.setConfig("StrictHostKeyChecking", "accept-new")
            session.timeout = 20000
            session.connect()
            val banner = session.serverVersion
            // No channel needed for the auth proof; disconnect politely.
            session.disconnect()
            return "userauth completed; server=$banner"
        } catch (e: Exception) {
            runCatching { session.disconnect() }
            throw e
        }
    }

    private fun sshString(b: ByteArray): ByteArray {
        val out = ByteArray(4 + b.size)
        var i = b.size
        out[3] = (i and 0xFF).toByte(); i = i shr 8
        out[2] = (i and 0xFF).toByte(); i = i shr 8
        out[1] = (i and 0xFF).toByte(); i = i shr 8
        out[0] = (i and 0xFF).toByte()
        b.copyInto(out, 4)
        return out
    }

    private fun outDir(): File = getExternalFilesDir(null) ?: cacheDir

    @Composable
    private fun Screen() {
        val share = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { }
        Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Column(
                modifier = Modifier.fillMaxSize().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text("Spike S2 — Keystore SSH identity", style = MaterialTheme.typography.titleMedium)
                Button(onClick = { ensureKey() }) { Text("1. Generate / load key") }
                Button(onClick = { testAuth("github.com") }) { Text("2. Test SSH auth to github.com") }
                Button(onClick = {
                    val f = File(outDir(), "id-offlinepass.pub")
                    if (f.exists()) {
                        val shareIntent = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_TEXT, f.readText())
                        }
                        share.launch(Intent.createChooser(shareIntent, "Share public key"))
                    } else setStatus("Generate the key first.")
                }) { Text("3. Share public key (for deploy-key enrollment)") }
                Text(status.value, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }

    companion object {
        private const val TAG = "S2"
    }
}
