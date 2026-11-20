package com.offlinepass.app.vault

import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

/**
 * The item-encryption toggle's OFF path: the sealed cache may be the sole
 * live copy of the secrets (the unlock→first-save window) — the toggle
 * must promote through the SAME primitive every save uses, and must
 * refuse rather than wipe when the promotion fails. A corrupt cache whose
 * manifest still lists items is the sharpest edge: the promote must NOT
 * mistake it for the empty-vault success.
 */
@RunWith(RobolectricTestRunner::class)
class ToggleOffNoDataLossTest {

    private lateinit var vaultFile: File

    @Before
    fun setup() {
        val app = RuntimeEnvironment.getApplication() as Context
        VaultSession.resetForTest(app)
        SealedVault.resetForTest(app)
        SealedVault.cryptoHook = fakeCrypto()
        vaultFile = File(VaultSession.vaultFilePath())
        vaultFile.parentFile?.mkdirs()
        vaultFile.writeText("ciphertext-blob-v1")
    }

    private fun fakeCrypto(): SealedVault.SealCrypto = object : SealedVault.SealCrypto {
        private val key = javax.crypto.spec.SecretKeySpec(
            ByteArray(32) { (it * 5 + 11).toByte() }, "AES")
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

    private fun seedCache(vararg items: ProtonItem) {
        // The ENROLLMENT'S ACT first: the toggle ON (the documented default
        // is off until the screenlock is enrolled).
        kotlinx.coroutines.runBlocking { VaultSession.setScreenlockUnlockEnabled(true) }
        val env = Envelope(rev = 3, deviceId = "d1")
        env.items = items.toMutableList()
        kotlinx.coroutines.runBlocking {
            SealedVault.sealNowAwait(items.toList(), env, vaultFile)
        }
        assertTrue(SealedVault.hasCache())
    }

    @Test
    fun toggleOffPromotesThenWipes_secretsSurviveInMemory() {
        SealedVault.cryptoHook = fakeCrypto()
        seedCache(
            ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a"),
            ProtonItem(name = "B", username = "ub", password = "pb", itemUuid = "u-b"))
        // The unlock shape: stubs in memory, the secrets only in the cache.
        VaultSession.stubSessionForTest()

        val msg = kotlinx.coroutines.runBlocking {
            VaultSession.setScreenlockUnlockEnabled(false)
        }

        assertTrue(msg.contains("OFF"))
        assertFalse("the cache wiped after the promote", SealedVault.hasCache())
        assertFalse(VaultSession.screenlockUnlockEnabled())
        // THE SECRETS SURVIVE — in memory, the full session.
        val items = (VaultSession.state as VaultSession.State.Unlocked).items
        assertEquals("pa", items.first { it.itemUuid == "u-a" }.password)
        assertEquals("pb", items.first { it.itemUuid == "u-b" }.password)
    }

    @Test
    fun toggleOffFallsBackToTheRepoDecryptWhenTheSealIsStale() {
        // A sync pulled a newer vault: the cache is stale (the promote
        // fails on freshness) — the toggle-off must still work: the repo
        // is the truth, and the fallback decrypts IT.
        seedCache(ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a"))
        VaultSession.stubSessionForTest()
        // The "newer vault": the file's bytes change after the seal.
        vaultFile.writeText("ciphertext-blob-v2-newer")
        VaultSession.vaultDecryptBytes = { bytes ->
            if (!String(bytes).contains("v2-newer")) error("wrong file")
            ("""{"rev":9,"deviceId":"d1","itemId":"i",
                "data":{"metadata":{"name":"A","itemUuid":"u-a"},
                "content":{"itemUsername":"ua","password":"pa-REPO"}}}""")
                .replace("\n", "").toByteArray()
        }

        val msg = kotlinx.coroutines.runBlocking {
            VaultSession.setScreenlockUnlockEnabled(false)
        }

        assertTrue(msg.contains("OFF"))
        assertFalse(SealedVault.hasCache())
        // THE SECRETS SURVIVE — from the REPO decrypt, not the stale cache.
        val items = (VaultSession.state as VaultSession.State.Unlocked).items
        assertEquals("pa-REPO", items.first { it.itemUuid == "u-a" }.password)
    }

    @Test
    fun toggleOffRefusesWhenBothPathsFail() {
        SealedVault.cryptoHook = fakeCrypto()
        seedCache(
            ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a"))
        VaultSession.stubSessionForTest()
        // Corrupt the blob: the manifest still lists u-a, but the unseal fails.
        val f = File(RuntimeEnvironment.getApplication().filesDir, "sealed/sealed.json")
        val raw = org.json.JSONObject(f.readText())
        raw.getJSONArray("items").getJSONObject(0).put("ct", "!!!not-base64!!!")
        f.writeText(raw.toString())

        val msg = kotlinx.coroutines.runBlocking {
            VaultSession.setScreenlockUnlockEnabled(false)
        }

        assertTrue("the refusal explains", msg.contains("Could not disable") &&
            msg.contains("Nothing was lost"))
        assertTrue("the pref UNCHANGED (the switch stays on)",
            VaultSession.screenlockUnlockEnabled())
        assertTrue("the cache INTACT", SealedVault.hasCache())
    }

    @Test
    fun corruptCachePromoteFailsRatherThanPromotingEmpty() {
        SealedVault.cryptoHook = fakeCrypto()
        seedCache(
            ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a"))
        VaultSession.stubSessionForTest()
        val f = File(RuntimeEnvironment.getApplication().filesDir, "sealed/sealed.json")
        val raw = org.json.JSONObject(f.readText())
        raw.getJSONArray("items").getJSONObject(0).put("ct", "!!!not-base64!!!")
        f.writeText(raw.toString())

        val r = kotlinx.coroutines.runBlocking { VaultSession.promoteSealedSession() }

        assertTrue(
            "the corrupt cache must NOT promote to an empty (data-loss) session",
            r is VaultSession.Result.Error)
        assertTrue(SealedVault.hasCache())
    }

    @Test
    fun toggleOffWhileLockedWipesSafely() {
        // No session (Locked): the cache is a mirror of the last save —
        // the repo envelope holds the same data — the wipe is safe.
        SealedVault.cryptoHook = fakeCrypto()
        seedCache(ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a"))

        val msg = kotlinx.coroutines.runBlocking {
            VaultSession.setScreenlockUnlockEnabled(false)
        }

        assertTrue(msg.contains("OFF"))
        assertFalse(SealedVault.hasCache())
        assertFalse(VaultSession.screenlockUnlockEnabled())
    }
}
