package com.offlinepass.app.autofill

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import com.offlinepass.app.crypto.ScreenlockGate
import com.offlinepass.app.vault.PasswordGen
import com.offlinepass.app.vault.ProtonItem
import com.offlinepass.app.vault.SealedVault
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
 *   fresh [PasswordGen.password] stored as the reveal-shaped item; the
 *   re-invoke fills the generated value into the tapped password field.
 *   NO MainActivity navigation in either mode — the control stays with
 *   the framework's fill flow.
 */
class AutofillAuthActivity : androidx.activity.ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        com.offlinepass.app.vault.VaultSession.init(applicationContext)
        com.offlinepass.app.vault.SealedVault.init(applicationContext)
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
                val item = ProtonItem(
                    name = name?.takeIf { it.isNotBlank() } ?: "Generated password",
                    password = PasswordGen.password())
                AutofillRevealStore.put(item, "generate")
                // THE SAVE OFFER = SELF-POSTED: the OS's onSaveRequest
                // SUPPRESSES the autofilled values (the save request =
                // the user-typed entries only) — the offer must go out
                // the moment the password is generated ("save it if
                // confirmed").
                AutofillSaveOffer.post(this@AutofillAuthActivity, item.name, null, item.password)
                Log.i(TAG, "generated a password for ${item.name} — RESULT_OK")
                setResult(RESULT_OK)
                finish()
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

    companion object {
        private const val TAG = "OfflinepassAutofill"
        const val EXTRA_UUID = "uuid"
        const val EXTRA_NAME = "name"
        const val EXTRA_MODE = "mode"
        const val MODE_REVEAL = "reveal"
        const val MODE_GENERATE = "generate"
    }
}
