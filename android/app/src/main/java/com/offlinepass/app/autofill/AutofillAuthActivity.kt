package com.offlinepass.app.autofill

import android.app.AlertDialog
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import com.offlinepass.app.crypto.ScreenlockGate
import com.offlinepass.app.vault.PasswordGen
import com.offlinepass.app.vault.ProtonItem
import com.offlinepass.app.vault.SealedVault
import com.offlinepass.app.vault.VaultSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The autofill's auth activity, three modes:
 * - **reveal** (default): the sealed-state chip's tapped item — the SAME
 *   screenlock gate as the item view; the TARGETED single item unseals,
 *   the store carries it to the framework's re-invoked onFillRequest.
 *   RESULT_OK = fill; canceled = the picker stays.
 * - **generate**: the "⚡ Generate password" chip — the gate, then a
 *   fresh [PasswordGen.password] into the store; RESULT_OK → the fill.
 *   NO save question here — the save comes AFTER the login.
 * - **save**: launched BY THE FRAMEWORK from onSaveRequest — i.e. only
 *   after the login completed (the user's sequencing: the interstitial
 *   = after the credentials' use). The screenlock gate → "Save this
 *   login to offlinepass?" [Save]/[Not now] — the save runs here with
 *   the app's standard prompt surfaces as dialogs (the security key's
 *   touch reminder, the OpenPGP PIN).
 *   NO MainActivity navigation in any mode — the control stays with the
 *   framework's flow.
 */
class AutofillAuthActivity : ComponentActivity() {

    private var touchDialog: AlertDialog? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        com.offlinepass.app.vault.VaultSession.init(applicationContext)
        com.offlinepass.app.vault.SealedVault.init(applicationContext)
        installPromptSurfaces()
        val mode = intent.getStringExtra(EXTRA_MODE) ?: MODE_REVEAL
        val uuid = intent.getStringExtra(EXTRA_UUID)
        val name = intent.getStringExtra(EXTRA_NAME)
        if (mode == MODE_REVEAL && uuid == null) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }
        lifecycleScope.launch {
            when (mode) {
                MODE_GENERATE -> {
                    val ok = ScreenlockGate.promptGate(
                        this@AutofillAuthActivity,
                        "Generate & fill",
                        "The device lock authorizes filling a generated password")
                    if (!ok) {
                        Log.i(TAG, "the generate's gate declined — RESULT_CANCELED")
                        setResult(RESULT_CANCELED)
                        finish()
                        return@launch
                    }
                    val origin = name?.takeIf { it.isNotBlank() } ?: "Generated password"
                    val item = ProtonItem(
                        name = origin,
                        // THE URL = THE ORIGIN's (the domain-shaped origins
                        // become the entry's urls).
                        urls = if (origin.contains('.') && !origin.contains(' '))
                            listOf("https://$origin") else emptyList(),
                        password = PasswordGen.password())
                    AutofillRevealStore.put(item, "generate")
                    // NO INTERSTITIAL HERE — the save = ONCE, after the
                    // form submission, via the framework's save request
                    // (the SAVE mode below; the platform fires it when a
                    // user-entered field changed — typing the username
                    // qualifies).
                    Log.i(TAG, "generated a password for $origin — RESULT_OK (the fill)")
                    setResult(RESULT_OK)
                    finish()
                }
                MODE_SAVE -> {
                    val origin = name?.takeIf { it.isNotBlank() } ?: "Login"
                    val item = ProtonItem(
                        name = origin,
                        username = intent.getStringExtra(EXTRA_USERNAME) ?: "",
                        // THE URL = THE ORIGIN's (the domain-shaped origins
                        // become the entry's urls — the add path's item).
                        urls = if (origin.contains('.') && !origin.contains(' '))
                            listOf("https://$origin") else emptyList(),
                        password = intent.getStringExtra(EXTRA_PASSWORD) ?: "")
                    val gate = ScreenlockGate.promptGate(
                        this@AutofillAuthActivity,
                        "Unlock offlinepass",
                        "The device lock authorizes saving the login")
                    if (!gate) {
                        Log.i(TAG, "the save's gate declined — done")
                        setResult(RESULT_OK)
                        finish()
                        return@launch
                    }
                    withContext(Dispatchers.Main) { showSaveInterstitial(item) }
                }
                else -> {
                    val item = withContext(Dispatchers.IO) { SealedVault.reveal(uuid!!) }
                    if (item == null) {
                        Log.w(TAG, "the unseal failed for ${uuid?.take(8)} — RESULT_CANCELED " +
                            "(the cache stale/missing — the app's unlock re-seals)")
                        setResult(RESULT_CANCELED)
                        finish()
                        return@launch
                    }
                    AutofillRevealStore.put(item, uuid)
                    Log.i(TAG, "revealed ${item.displayName} — RESULT_OK (the framework re-invokes)")
                    setResult(RESULT_OK)
                    finish()
                }
            }
        }
    }

    /** THE SAVE INTERSTITIAL — after the login, on the framework's
     *  launch: [Save] = the sealed save here (the dialogs cover the card
     *  prompts); [Not now] = done. Either way RESULT_OK. */
    private fun showSaveInterstitial(item: ProtonItem) {
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(64, 96, 64, 48)
        }
        col.addView(TextView(this).apply {
            text = "Save this login to offlinepass?"
            textSize = 20f
        })
        col.addView(TextView(this).apply {
            text = "${item.name}\n${item.username.takeIf { it.isNotBlank() }?.let { "$it\n" } ?: ""}" +
                "Save it with your security key's protection."
            textSize = 14f
        })
        col.addView(Button(this).apply {
            text = "Save"
            setOnClickListener {
                it.isEnabled = false
                lifecycleScope.launch {
                    // THE ADD PATH: the generated entry = brand-new — the
                    // EDIT path (saveSealed) silently no-ops for it (the
                    // swap-by-uuid never matched — the measured "Saved ✓
                    // but 3 items sealed").
                    val r = try {
                        VaultSession.addSealed(item.copy(modifyTime = 0))
                    } catch (e: Exception) {
                        VaultSession.Result.Error("${e.javaClass.simpleName}: ${e.message}")
                    }
                    when (r) {
                        VaultSession.Result.Success -> {
                            Log.i(TAG, "the interstitial save: Saved ✓ " +
                                "(rev ${VaultSession.currentRev()})")
                            Toast.makeText(this@AutofillAuthActivity,
                                "Saved ✓", Toast.LENGTH_LONG).show()
                            setResult(RESULT_OK)
                            finish()
                        }
                        else -> {
                            // LOUD: the failure = the retry stays available
                            // (the silence = the measured "probably not saved").
                            Log.w(TAG, "the interstitial save FAILED: $r")
                            Toast.makeText(this@AutofillAuthActivity,
                                "The save failed — $r", Toast.LENGTH_LONG).show()
                            it.isEnabled = true
                        }
                    }
                }
            }
        })
        col.addView(Button(this).apply {
            text = "Not now"
            setOnClickListener {
                Log.i(TAG, "the save declined — done")
                setResult(RESULT_OK)
                finish()
            }
        })
        setContentView(col)
    }

    /** The prompt surfaces for the in-activity save: the touch reminder +
     *  the OpenPGP PIN — the SAME hooks MainActivity installs, pointed at
     *  this activity's dialogs (the interstitials the user referenced). */
    private fun installPromptSurfaces() {
        VaultSession.openPgpPinPrompt = {
            kotlinx.coroutines.suspendCancellableCoroutine { cont ->
                runOnUiThread {
                    val input = EditText(this).apply {
                        inputType = android.text.InputType.TYPE_CLASS_NUMBER
                    }
                    AlertDialog.Builder(this)
                        .setTitle("OpenPGP PIN")
                        .setView(input)
                        .setPositiveButton("OK") { _, _ ->
                            cont.resume(input.text.toString().toCharArray(), null)
                        }
                        .setNegativeButton("Cancel") { _, _ -> cont.resume(null, null) }
                        .show()
                }
            }
        }
        // The touch reminder: poll the session's flag — the same dialog
        // MainActivity's router renders, here as a plain dialog.
        lifecycleScope.launch {
            while (true) {
                kotlinx.coroutines.delay(150)
                val wants = withContext(Dispatchers.Main) { VaultSession.touchPrompt }
                if (wants && touchDialog == null) {
                    touchDialog = AlertDialog.Builder(this@AutofillAuthActivity)
                        .setTitle("🔐 Touch your YubiKey")
                        .setMessage("The key is waiting — touch it (the LED blinks).")
                        .setCancelable(false)
                        .show()
                } else if (!wants && touchDialog != null) {
                    touchDialog?.dismiss()
                    touchDialog = null
                }
            }
        }
    }

    companion object {
        private const val TAG = "OfflinepassAutofill"
        const val EXTRA_UUID = "uuid"
        const val EXTRA_NAME = "name"
        const val EXTRA_MODE = "mode"
        const val EXTRA_USERNAME = "username"
        const val EXTRA_PASSWORD = "password"
        const val MODE_REVEAL = "reveal"
        const val MODE_GENERATE = "generate"
        const val MODE_SAVE = "save"
    }
}
