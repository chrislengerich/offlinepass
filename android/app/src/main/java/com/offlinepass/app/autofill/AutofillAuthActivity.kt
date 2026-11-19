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
 *   RESULT_OK = fill; canceled = the picker stays. The unseal NEVER
 *   escapes: the keystore's auth window can lag the device-credential
 *   gate on this ROM (the measured UserNotAuthenticatedException crash)
 *   — the failure = one gate retry, then a clean RESULT_CANCELED.
 * - **generate**: the "⚡ Generate password" chip — the gate, then a
 *   fresh [PasswordGen.password] into the store; RESULT_OK → the fill.
 * - **save**: launched BY THE FRAMEWORK from onSaveRequest — after the
 *   form submission. THE USER'S ORDERING: the question first ("Save
 *   this login to offlinepass?" — one [Save] click), THEN the screenlock
 *   gate, THEN the save (the INSERT path — the autofill's items carry
 *   fresh uuids; no origin matching, no updates).
 *   NO MainActivity navigation in any mode.
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
                        urls = if (origin.contains('.') && !origin.contains(' '))
                            listOf("https://$origin") else emptyList(),
                        password = PasswordGen.password())
                    AutofillRevealStore.put(item, "generate")
                    // THE FLYUP = SELF-POSTED AT THE GENERATE: the platform's
                    // save event = the user-changed-fields only — an
                    // all-autofilled submission fires NOTHING (the measured
                    // no-flyup). The banner = NON-BLOCKING: it sits while
                    // the user completes the form; the tap = the yes (the
                    // screenlock → the insert), the swipe = the no.
                    AutofillSaveOffer.post(this@AutofillAuthActivity, origin, null, item.password)
                    Log.i(TAG, "generated a password for $origin — RESULT_OK (the fill) + the flyup")
                    setResult(RESULT_OK)
                    finish()
                }
                MODE_SAVE -> {
                    // THE BANNER = THE QUESTION: the tap = the yes — the
                    // gate → the insert directly (no second question UI).
                    val origin = name?.takeIf { it.isNotBlank() } ?: "Login"
                    val item = ProtonItem(
                        name = origin,
                        username = intent.getStringExtra(EXTRA_USERNAME) ?: "",
                        urls = if (origin.contains('.') && !origin.contains(' '))
                            listOf("https://$origin") else emptyList(),
                        password = intent.getStringExtra(EXTRA_PASSWORD) ?: "")
                    val gate = ScreenlockGate.promptGate(
                        this@AutofillAuthActivity,
                        "Unlock offlinepass",
                        "The device lock authorizes saving the login")
                    if (!gate) {
                        Log.i(TAG, "the save's gate declined")
                        Toast.makeText(this@AutofillAuthActivity,
                            "Not saved — the screen lock declined", Toast.LENGTH_LONG).show()
                        setResult(RESULT_OK)
                        finish()
                        return@launch
                    }
                    val r = try {
                        VaultSession.addSealed(item.copy(modifyTime = 0))
                    } catch (e: Exception) {
                        VaultSession.Result.Error("${e.javaClass.simpleName}: ${e.message}")
                    }
                    when (r) {
                        VaultSession.Result.Success -> {
                            Log.i(TAG, "the banner save: Saved ✓ (rev ${VaultSession.currentRev()})")
                            Toast.makeText(this@AutofillAuthActivity,
                                "Saved ✓", Toast.LENGTH_LONG).show()
                            setResult(RESULT_OK)
                            finish()
                        }
                        else -> {
                            Log.w(TAG, "the banner save FAILED: $r")
                            Toast.makeText(this@AutofillAuthActivity,
                                "The save failed — $r", Toast.LENGTH_LONG).show()
                            setResult(RESULT_OK)
                            finish()
                        }
                    }
                }
                else -> {
                    // THE REVEAL: the unseal never escapes — the keystore's
                    // window can lag the credential gate (the measured
                    // crash): one gate retry, then the clean cancellation.
                    val gate = ScreenlockGate.promptGate(
                        this@AutofillAuthActivity,
                        "Unlock the entry",
                        "Autofill: the device lock opens this item's secrets")
                    if (!gate) {
                        Log.i(TAG, "auth gate declined — RESULT_CANCELED")
                        setResult(RESULT_CANCELED)
                        finish()
                        return@launch
                    }
                    var item: ProtonItem? = try {
                        withContext(Dispatchers.IO) { SealedVault.reveal(uuid!!) }
                    } catch (e: Exception) {
                        Log.w(TAG, "the unseal threw (${e.javaClass.simpleName}) — " +
                            "the gate retry")
                        null
                    }
                    if (item == null) {
                        // The window lag: ONE retry behind a fresh gate.
                        val again = ScreenlockGate.promptGate(
                            this@AutofillAuthActivity,
                            "Unlock the entry",
                            "One more device-lock press to open the entry")
                        if (again) {
                            item = try {
                                withContext(Dispatchers.IO) { SealedVault.reveal(uuid!!) }
                            } catch (e: Exception) {
                                Log.w(TAG, "the retry unseal threw (${e.javaClass.simpleName})")
                                null
                            }
                        }
                    }
                    if (item == null) {
                        Log.w(TAG, "the unseal failed for ${uuid?.take(8)} — RESULT_CANCELED")
                        Toast.makeText(this@AutofillAuthActivity,
                            "Couldn't open the entry — unlock the app once, then retry",
                            Toast.LENGTH_LONG).show()
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
