package com.offlinepass.app.autofill

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import com.offlinepass.app.crypto.ScreenlockGate
import com.offlinepass.app.vault.SealedVault
import kotlinx.coroutines.Dispatchers
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The sealed-state autofill's auth activity: the SAME screenlock gate as
 * the item view — the device credential opens the keystore window, the
 * TARGETED single item unseals, the store carries it to the framework's
 * re-invoked onFillRequest. RESULT_OK = fill; canceled = the picker stays.
 */
class AutofillAuthActivity : androidx.activity.ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uuid = intent.getStringExtra(EXTRA_UUID)
        if (uuid == null) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }
        lifecycleScope.launch {
            val ok = ScreenlockGate.promptGate(
                this@AutofillAuthActivity,
                "Unlock the entry",
                "Autofill: the device lock opens this item's secrets")
            if (!ok) {
                setResult(RESULT_CANCELED)
                finish()
                return@launch
            }
            val item = withContext(Dispatchers.IO) { SealedVault.reveal(uuid) }
            if (item == null) {
                setResult(RESULT_CANCELED)
                finish()
                return@launch
            }
            AutofillRevealStore.put(item)
            setResult(RESULT_OK)
            finish()
        }
    }

    companion object {
        const val EXTRA_UUID = "uuid"
    }
}
