package com.offlinepass.app.spike

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.offlinepass.app.vault.VaultGitClient
import java.io.File
import java.util.Date

/**
 * Spike S3 — the real transport: JGit clone/fetch/commit/push over HTTPS
 * with a fine-grained PAT, against the private test repo.
 *
 * ADB-driven: push the PAT to the app's external files dir as
 * `storage-pat.txt`, then launch (optionally --es remote <url> and
 * --es autostart 1).
 */
class S3GitActivity : ComponentActivity() {

    private val status = mutableStateOf("Push storage-pat.txt to the app dir, then run.")

    private fun setStatus(t: String) {
        status.value = t
        Log.i(TAG, t)
    }

    private fun outDir(): File = getExternalFilesDir(null) ?: cacheDir

    private fun pat(): String? =
        File(outDir(), "storage-pat.txt").takeIf { it.exists() }?.readText()?.trim()?.takeIf { it.isNotEmpty() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                Column(
                    modifier = Modifier.fillMaxSize().padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text("Spike S3 — JGit HTTPS+PAT transport", style = MaterialTheme.typography.titleMedium)
                    Button(onClick = { runSyncTest() }) { Text("Run git sync test") }
                    Button(onClick = { runEndpointProbe() }) { Text("Probe push/fetch endpoints") }
                    Text(status.value, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
        if (intent.getStringExtra("autostart") != null) runSyncTest()
    }

    private fun runSyncTest() {
        val pat = pat() ?: run { setStatus("NO PAT: push storage-pat.txt first."); return }
        val remote = intent.getStringExtra("remote")
            ?: "https://github.com/planetaltitude/offlinepass-storage-test.git"
        setStatus("Sync test against $remote…")
        lifecycleScope.launch {
            try {
                val head = withContext(Dispatchers.IO) {
                    val client = VaultGitClient()
                    val root = File(filesDir, "sync-test")
                    // A previous failed clone leaves a non-repo dir behind,
                    // which would block the next clone.
                    if (root.exists() && !File(root, ".git").exists()) root.deleteRecursively()
                    client.open(remote, pat, root)
                    val log = File(root, "sync-test-log.txt")
                    log.appendText("sync ${Date()}\n")
                    client.commitAndPush(remote, pat, root, "sync test ${Date()}")
                }
                setStatus("SYNC OK head=$head")
            } catch (e: Exception) {
                setStatus("SYNC FAILED: ${e.javaClass.simpleName}: ${e.message}")
            }
        }
    }

    /** Raw HTTP probe of both git smart-HTTP endpoints — separates token
     * authorization (403) from transport issues. */
    private fun runEndpointProbe() {
        lifecycleScope.launch {
            val pat = pat() ?: run { setStatus("NO PAT"); return@launch }
            val remote = (intent.getStringExtra("remote")
                ?: "https://github.com/planetaltitude/offlinepass-storage-test.git").removeSuffix("/")
            withContext(Dispatchers.IO) {
                for (service in listOf("git-upload-pack", "git-receive-pack")) {
                    val conn = java.net.URL("$remote/info/refs?service=$service").openConnection()
                        as java.net.HttpURLConnection
                    val auth = java.util.Base64.getEncoder()
                        .encodeToString("x-access-token:$pat".toByteArray())
                    conn.setRequestProperty("Authorization", "Basic $auth")
                    conn.connectTimeout = 15000
                    conn.readTimeout = 15000
                    try {
                        val body = if (conn.responseCode in 200..299) conn.inputStream.bufferedReader().readText() else conn.errorStream?.bufferedReader()?.readText()
                        setStatus("PROBE $service → HTTP ${conn.responseCode} ${body?.take(100)}")
                    } catch (e: Exception) {
                        setStatus("PROBE $service → ${e.javaClass.simpleName}: ${e.message}")
                    } finally {
                        conn.disconnect()
                    }
                }
            }
        }
    }

    companion object {
        private const val TAG = "S3"
    }
}
