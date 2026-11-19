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
 * The autofill's auth activity, two modes:
 * - **reveal** (default): the sealed-state chip's tapped item — the SAME
 *   screenlock gate as the item view; the TARGETED single item unseals,
 *   the store carries it to the framework's re-invoked onFillRequest.
 *   RESULT_OK = fill; canceled = the picker stays.
 * - **generate**: the "⚡ Generate password" chip — the same gate, then a
 *   fresh [PasswordGen.password], and THE SAVE INTERSTITIAL IN THIS
 *   ACTIVITY: "Save this login to offlinepass?" [Save]/[Not now] — the
 *   user is already looking at this screen; the notification form was
 *   too noisy (the measured feedback). The Save = VaultSession.saveSealed
 *   right here, with the app's standard prompt surfaces replicated as
 *   dialogs (the security key's touch reminder, the OpenPGP PIN).
 *   NO MainActivity navigation in either mode — the control stays with
 *   the framework's fill flow.
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
            val ok = ScreenlockGate.promptGate(
                this@AutofillAuthActivity,
                if (mode == MODE_GENERATE) "Generate & fill" else "Unlock the entry",
                if (mode == MODE_GENERATE)
                    "The device lock authorizes filling a generated password"
                else "Autofill: the device lock opens this item's secrets")
            if (!ok) {
                Log.i(TAG, "auth gate declined ($mode) — RESULT_CANCELED")
                setResult(RESULT_CANCELED)
                finish()
                return@launch
            }
            if (mode == MODE_GENERATE) {
                val origin = name?.takeIf { it.isNotBlank() } ?: "Generated password"
                val item = ProtonItem(name = origin, password = PasswordGen.password())
                AutofillRevealStore.put(item, "generate")
                Log.i(TAG, "generated a password for $origin — the save interstitial")
                showSaveInterstitial(item)
                return@launch
            }
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

    /** THE SAVE INTERSTITIAL: the question lives in the flow the user is
     *  already in — [Save] = the sealed save here (the dialogs cover the
     *  card prompts); [Not now] = the fill only. Either way RESULT_OK:
     *  the framework fills the generated password regardless. */
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
            text = "${item.name} — the generated password.\n" +
                "The fill continues either way."
            textSize = 14f
        })
        col.addView(Button(this).apply {
            text = "Save"
            setOnClickListener {
                it.isEnabled = false
                lifecycleScope.launch {
                    val r = VaultSession.saveSealed(item.copy(modifyTime = 0))
                    val msg = when (r) {
                        VaultSession.Result.Success -> "Saved ✓"
                        else -> "The save failed: $r"
                    }
                    Log.i(TAG, "the interstitial save: $msg")
                    Toast.makeText(this@AutofillAuthActivity, msg, Toast.LENGTH_LONG).show()
                    setResult(RESULT_OK)
                    finish()
                }
            }
        })
        col.addView(Button(this).apply {
            text = "Not now"
            setOnClickListener {
                Log.i(TAG, "the save declined — the fill continues")
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
        const val MODE_REVEAL = "reveal"
        const val MODE_GENERATE = "generate"
    }
}
