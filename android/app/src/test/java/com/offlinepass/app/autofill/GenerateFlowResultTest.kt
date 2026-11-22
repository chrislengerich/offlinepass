package com.offlinepass.app.autofill

import android.app.AlertDialog
import android.content.Intent
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.service.autofill.FillResponse
import com.offlinepass.app.crypto.ScreenlockGate
import com.offlinepass.app.vault.Envelope
import com.offlinepass.app.vault.SealedVault
import com.offlinepass.app.vault.VaultSession
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController

/**
 * THE FULL-FLOW RESULT CONTRACT (the failing-test detector for the
 * post-generate fill): the ⚡/✨ flows MUST return the filled response
 * via EXTRA_AUTHENTICATION_RESULT — the framework applies it directly in
 * onAuthenticationResult; an empty auth result = the re-offered chip
 * (the measured regression: the browser's log showed
 * "onAuthenticationResult(): empty intent" and the generated login came
 * back as one more selectable chip instead of filling). The gate is
 * stubbed (the real BiometricPrompt is untestable in the JVM) so the
 * whole flow runs: the gate → the generation → the save card → the Save
 * → the upsert attempt.
 */
@RunWith(RobolectricTestRunner::class)
class GenerateFlowResultTest {

    private val app = RuntimeEnvironment.getApplication()

    private fun fid(): AutofillId =
        AutofillId::class.java.getDeclaredConstructor().apply { isAccessible = true }
            .newInstance() as AutofillId

    private fun fields() = OfflinepassAutofillService.Fields(
        username = listOf(fid()), password = listOf(fid()),
        appPackage = "app.vanadium.browser", webDomain = "github.com")

    /** setupService attaches the base context — generateIntent reads it. */
    private val svc = Robolectric.setupService(OfflinepassAutofillService::class.java)

    private fun generateIntent(mode: String): Intent =
        svc.generateIntent(mode, "github.com", fields())

    /** The sealed vault (the software seal — the keystore is unavailable
     *  under Robolectric) so the save's upsert path runs for real. */
    private fun installSealedVault() {
        VaultSession.init(app)
        SealedVault.resetForTest(app)
        SealedVault.cryptoHook = object : SealedVault.SealCrypto {
            private val key = javax.crypto.spec.SecretKeySpec(
                ByteArray(32) { (it * 7 + 3).toByte() }, "AES")
            override fun seal(plain: ByteArray, aad: ByteArray): Pair<ByteArray, ByteArray> {
                val iv = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
                val c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
                c.init(javax.crypto.Cipher.ENCRYPT_MODE, key,
                    javax.crypto.spec.GCMParameterSpec(128, iv))
                c.updateAAD(aad)
                return iv to c.doFinal(plain)
            }
            override fun unseal(iv: ByteArray, ct: ByteArray, aad: ByteArray): ByteArray {
                val c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
                c.init(javax.crypto.Cipher.DECRYPT_MODE, key,
                    javax.crypto.spec.GCMParameterSpec(128, iv))
                c.updateAAD(aad)
                return c.doFinal(ct)
            }
        }
        VaultSession.adopt(Envelope(deviceId = "t").also { e ->
            e.rev = 1
            e.items = mutableListOf()
        })
    }

    private fun runFlow(mode: String): Pair<ActivityController<AutofillAuthActivity>, AutofillAuthActivity> {
        installSealedVault()
        ScreenlockGate.testGate = { _, _, _ -> true }
        val controller = Robolectric.buildActivity(
            AutofillAuthActivity::class.java, generateIntent(mode))
        val activity = controller.create().start().visible().get()
        shadowOf(android.os.Looper.getMainLooper()).idle()
        return controller to activity
    }

    private fun tapSave() {
        shadowOf(android.os.Looper.getMainLooper()).idle()
        val dialog = org.robolectric.shadows.ShadowAlertDialog.getLatestAlertDialog()
        assertNotNull("the save card must be shown", dialog)
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
        shadowOf(android.os.Looper.getMainLooper()).idle()
    }

    @Test
    fun `the password flow returns the fill response in the auth result`() {
        val (controller, activity) = runFlow(AutofillAuthActivity.MODE_GENERATE)
        try {
            // THE REVEAL STORE ARMED (the fallback path's fuel).
            val stored = AutofillRevealStore.peek()
            assertNotNull("the generated item armed", stored)
            assertTrue("the 16-char alphanumeric default",
                stored!!.password.length == 16 &&
                    stored.password.all { it.isLetterOrDigit() })

            tapSave()

            // THE RESULT CONTRACT: the auth result carries the response.
            val resultIntent = shadowOf(activity).getResultIntent()
            assertNotNull("the result intent must exist", resultIntent)
            val response = resultIntent.getParcelableExtra<FillResponse>(
                AutofillManager.EXTRA_AUTHENTICATION_RESULT)
            assertNotNull("THE FILL MUST RIDE THE AUTH RESULT " +
                "(the empty intent = the re-offered-chip regression)", response)
        } finally {
            ScreenlockGate.testGate = null
            controller.destroy()
        }
    }

    @Test
    fun `the alias flow returns the fill response even when the alias fails`() {
        // The SL link is absent in this vault — the chain degrades to the
        // password-only fill, and THAT still must ride the auth result
        // (the degradation is visible in the card, never a dead result).
        val (controller, activity) = runFlow(AutofillAuthActivity.MODE_GENERATE_ALIAS)
        try {
            val stored = AutofillRevealStore.peek()
            assertNotNull("the password-only item armed", stored)
            val resultIntent = shadowOf(activity).getResultIntent()
            val response = resultIntent?.getParcelableExtra<FillResponse>(
                AutofillManager.EXTRA_AUTHENTICATION_RESULT)
            assertNotNull("the password-only degradation still fills", response)
        } finally {
            ScreenlockGate.testGate = null
            controller.destroy()
        }
    }
}
