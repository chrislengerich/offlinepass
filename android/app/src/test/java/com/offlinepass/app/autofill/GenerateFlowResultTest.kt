package com.offlinepass.app.autofill

import android.content.Intent
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.service.autofill.Dataset
import com.offlinepass.app.crypto.ScreenlockGate
import com.offlinepass.app.vault.Envelope
import com.offlinepass.app.vault.ProtonItem
import com.offlinepass.app.vault.SealedVault
import com.offlinepass.app.vault.VaultSession
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import java.io.File

/**
 * THE FULL-FLOW CONTRACT (the failing-test detector for the post-generate
 * fill): the ⚡/✨ flows MUST auto-save the login (the sealed cache's rev
 * bumps, the manifest carries the record) AND return the filled response
 * via EXTRA_AUTHENTICATION_RESULT — the framework applies it directly in
 * onAuthenticationResult; an empty auth result = the re-offered chip (the
 * measured regression: the browser's log showed
 * "onAuthenticationResult(): empty intent" and the generated login came
 * back as one more selectable chip instead of filling — the old save card
 * + the second gate stretched the flow past the autofill session's life,
 * which is why the save now runs in-flow and the finish fires fast). The
 * gate is stubbed (the real BiometricPrompt is untestable in the JVM) so
 * the whole flow runs.
 *
 * THE ASSERTS = THE SEALED CACHE (durable, survives the activity's
 * zero-on-exit by design — the in-memory session is wiped when the auth
 * activity finishes): the cache's rev bumps on the save, the manifest
 * carries the record, and the update keeps the seeded item's uuid.
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

    private fun cacheFile(): File = File(File(app.filesDir, "sealed"), "sealed.json")

    private fun cacheRev(): Int = runCatching {
        JSONObject(cacheFile().readText()).optInt("rev", 0)
    }.getOrDefault(0)

    private fun cacheManifest(): List<ProtonItem> = runCatching {
        val arr = JSONObject(cacheFile().readText()).optJSONArray("items")
        (0 until arr!!.length()).mapNotNull { i ->
            val o = arr.optJSONObject(i) ?: return@mapNotNull null
            ProtonItem(
                name = o.optString("name"), username = o.optString("username"),
                email = o.optString("email"), itemUuid = o.optString("uuid"),
                urls = o.optJSONArray("urls")?.let { a ->
                    (0 until a.length()).map { a.getString(it) }
                } ?: emptyList())
        }
    }.getOrDefault(emptyList())

    /** The sealed vault (the software seal — the keystore is unavailable
     *  under Robolectric) seeded with [seed], and the repo state ready. */
    /** The OpenKeyChain stub (the device-only IPC): every op succeeds. */
    private class FakeOpenPgp : com.offlinepass.app.crypto.OpenPgpOps {
        override suspend fun lookupKeyIds(
            userIds: Array<String>, requestData: android.content.Intent?
        ) = com.offlinepass.app.crypto.OpenPgpClient.KeyLookup.Success(longArrayOf(KEY_ID))
        override suspend fun encryptTo(
            keyIds: LongArray, source: File, target: File
        ): Boolean {
            target.writeText("ciphertext:${source.readText().hashCode()}")
            return true
        }
        override suspend fun fetchPublicKeyArmored(
            keyId: Long, requestData: android.content.Intent?
        ) = com.offlinepass.app.crypto.OpenPgpClient.PublicKey.Success(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----")
        override suspend fun trySignDetached(
            data: ByteArray, keyId: Long?, requestData: android.content.Intent?, apiVersion: Int
        ) = com.offlinepass.app.crypto.OpenPgpClient.SignDetached.Ok(
            "-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----")
        override suspend fun pickSignKey(
            requestData: android.content.Intent?
        ) = com.offlinepass.app.crypto.OpenPgpClient.SignKey.Picked(KEY_ID, "test-user")
        companion object { const val KEY_ID = 0x1122334455667788L }
    }

    private fun installSealedVault(vararg seed: ProtonItem) {
        VaultSession.resetForTest(app)
        VaultSession.init(app)
        SealedVault.resetForTest(app)
        // THE SAVE's repo commit = the OpenKeyChain IPC — stubbed.
        VaultSession.openPgpClientFactory = { FakeOpenPgp() }
        VaultSession.vaultEncryptBytes = { plain, _, _ ->
            java.util.Base64.getEncoder().encode(plain)
        }
        VaultSession.vaultDecryptBytes = { bytes ->
            java.util.Base64.getDecoder().decode(bytes)
        }
        VaultSession.setRecipientKeyIds(listOf(FakeOpenPgp.KEY_ID))
        VaultSession.configure(null, listOf("user@example.com"))
        kotlinx.coroutines.runBlocking { VaultSession.setScreenlockUnlockEnabled(true) }
        // THE SOFTWARE SEAL (the keystore is unavailable under Robolectric)
        // — the adopt's sealIfEnabled writes the cache via this hook.
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
            e.items = mutableListOf(*seed)
        })
    }

    private fun runFlow(mode: String, vararg seed: ProtonItem): AutofillAuthActivity {
        installSealedVault(*seed)
        ScreenlockGate.testGate = { _, _, _ -> true }
        val controller = Robolectric.buildActivity(
            AutofillAuthActivity::class.java, generateIntent(mode))
        val activity = controller.create().start().visible().get()
        // The flow's save = the async (the seal + the repo commit on the
        // IO) — pump the looper until the sealed cache's rev bumps past
        // the adoption's rev (the save landed durably).
        val base = 1 + seed.size
        val deadline = System.currentTimeMillis() + 10_000
        while (cacheRev() < base && System.currentTimeMillis() < deadline) {
            Thread.sleep(20)
            shadowOf(android.os.Looper.getMainLooper()).idle()
        }
        return activity
    }

    @Test
    fun `the password flow auto-saves and returns the fill response`() {
        val activity = runFlow(AutofillAuthActivity.MODE_GENERATE)
        // THE RESULT CONTRACT: the auth result carries the response.
        val resultIntent = shadowOf(activity).getResultIntent()
        assertNotNull("the result intent must exist", resultIntent)
        val response = resultIntent.getParcelableExtra<Dataset>(
            AutofillManager.EXTRA_AUTHENTICATION_RESULT)
        assertNotNull("THE FILL MUST RIDE THE AUTH RESULT " +
            "(the empty intent = the re-offered-chip regression)", response)
        // THE AUTO-SAVE LANDED: the manifest = the login.
        val manifest = cacheManifest()
        assertEquals("the upsert appended the login", 1, manifest.size)
        assertEquals("github.com", manifest[0].name)
    }

    @Test
    fun `the alias flow auto-saves the degraded password and returns the response`() {
        // The SL link is absent in this vault — the chain degrades to the
        // password-only fill (the toast says why), and THAT still must
        // ride the auth result and save.
        val activity = runFlow(AutofillAuthActivity.MODE_GENERATE_ALIAS)
        val resultIntent = shadowOf(activity).getResultIntent()
        val response = resultIntent?.getParcelableExtra<Dataset>(
            AutofillManager.EXTRA_AUTHENTICATION_RESULT)
        assertNotNull("the password-only degradation still fills", response)
        assertEquals("the degraded save landed", 1, cacheManifest().size)
    }

    @Test
    fun `the same-identity login updates in place - one record`() {
        // The seeded login (the username blank, the same site) = the SAME
        // identity as the ⚡ flow's item — the auto-save UPDATES instead
        // of appending a duplicate.
        val seeded = ProtonItem(
            name = "github.com", username = "", password = "pw-old",
            urls = listOf("https://github.com"))
        val activity = runFlow(AutofillAuthActivity.MODE_GENERATE, seeded)
        val resultIntent = shadowOf(activity).getResultIntent()
        assertNotNull(resultIntent.getParcelableExtra<Dataset>(
            AutofillManager.EXTRA_AUTHENTICATION_RESULT))
        assertEquals("the update, not the append: one record",
            1, cacheManifest().size)
    }
}
