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
        // The decrypt seam DEAD (both paths must fail): the corrupt cache
        // kills the promote AND no card exists to decrypt the repo.
        VaultSession.vaultDecryptBytes = { error("no card under test") }
        // Corrupt the blob: the manifest still lists u-a, but the unseal fails.
        val f = File(RuntimeEnvironment.getApplication().filesDir, "sealed/sealed.json")
        val raw = org.json.JSONObject(f.readText())
        raw.getJSONArray("items").getJSONObject(0).put("ct", "!!!not-base64!!!")
        f.writeText(raw.toString())

        val msg = kotlinx.coroutines.runBlocking {
            VaultSession.setScreenlockUnlockEnabled(false)
        }

        assertTrue("the refusal explains: $msg", msg.contains("Could not disable") &&
            msg.contains("Nothing was lost"))
        assertTrue("the pref UNCHANGED (the switch stays on)",
            VaultSession.screenlockUnlockEnabled())
        assertTrue("the cache INTACT", SealedVault.hasCache())
    }

    @Test
    fun corruptCacheFullPromoteFailsRatherThanPromotingEmpty() {
        // THE DATA-LOSS GUARD = THE WRITE OPS' PROMOTE: the corrupt cache
        // must not promote into a session the SAVE trusts as the diff
        // base. (The unlock path's FAST promote browses on the public
        // manifest alone — see corruptCacheFastPromoteStillBrowses.)
        SealedVault.cryptoHook = fakeCrypto()
        seedCache(
            ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a"))
        VaultSession.stubSessionForTest()
        val f = File(RuntimeEnvironment.getApplication().filesDir, "sealed/sealed.json")
        val raw = org.json.JSONObject(f.readText())
        raw.getJSONArray("items").getJSONObject(0).put("ct", "!!!not-base64!!!")
        f.writeText(raw.toString())

        val r = kotlinx.coroutines.runBlocking { VaultSession.promoteSealedSessionFull() }

        assertTrue(
            "the corrupt cache must NOT promote to an empty (data-loss) session",
            r is VaultSession.Result.Error)
        assertTrue(SealedVault.hasCache())
    }

    @Test
    fun corruptCacheFastPromoteStillBrowses() {
        // THE FAST PROMOTE'S CONTRACT: the unlock path promotes from the
        // PUBLIC manifest alone — no unseal, zero Keystore ops (the 13s →
        // instant fix). A corrupt secret blob does NOT block browsing:
        // the data-loss guard lives in the write ops (promoteIfStub → the
        // full promote fails → the save refuses honestly), never in a
        // browse that touches neither the secrets nor the vault file.
        SealedVault.cryptoHook = fakeCrypto()
        seedCache(
            ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a"))
        VaultSession.stubSessionForTest()
        val f = File(RuntimeEnvironment.getApplication().filesDir, "sealed/sealed.json")
        val raw = org.json.JSONObject(f.readText())
        raw.getJSONArray("items").getJSONObject(0).put("ct", "!!!not-base64!!!")
        f.writeText(raw.toString())

        val r = kotlinx.coroutines.runBlocking { VaultSession.promoteSealedSession() }

        assertTrue("the fast promote browses on the manifest alone ($r)",
            r is VaultSession.Result.Success)
        assertTrue(VaultSession.state is VaultSession.State.Unlocked)
        val stubs = (VaultSession.state as VaultSession.State.Unlocked).items
        assertEquals("the manifest stub survives", "A", stubs.firstOrNull()?.name)
        assertTrue("the corrupt cache stays (nothing destroyed)", SealedVault.hasCache())
    }

    @Test
    fun toggleOffWithRetiredFormatCacheFallsBackToo() {
        // A v1 (retired-format) cache: the promote refuses; the repo
        // decrypt path still works — the toggle-off proceeds.
        SealedVault.cryptoHook = fakeCrypto()
        seedCache(ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a"))
        VaultSession.stubSessionForTest()
        val f = File(RuntimeEnvironment.getApplication().filesDir, "sealed/sealed.json")
        val raw = org.json.JSONObject(f.readText()); raw.put("v", 1)
        f.writeText(raw.toString())
        VaultSession.vaultDecryptBytes = { bytes ->
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
    }

    @Test
    fun sealedPromoteNeverTouchesTheCardDecrypt() {
        // THE TRIPWIRE: the sealed fast unlock (the idle-locked re-unlock)
        // must work from the cache alone — the decrypt seam is pinned
        // dead; if the promote EVER reaches for the card, this fails.
        SealedVault.cryptoHook = fakeCrypto()
        seedCache(
            ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a"))
        VaultSession.vaultDecryptBytes = { error("no card under test") }

        val r = kotlinx.coroutines.runBlocking { VaultSession.promoteSealedSession() }

        assertTrue("the promote works from the cache alone ($r)",
            r is VaultSession.Result.Success)
        val stubs = (VaultSession.state as VaultSession.State.Unlocked).items
        assertTrue("the promoted session is stubbed", stubs.first().password.isEmpty())
    }

    @Test
    fun toggleOnGatesImmediately_noAppRestartNeeded() {
        SealedVault.cryptoHook = fakeCrypto()
        seedCache(
            ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a"))
        // The toggle-off leaves the FULL session (the secrets in memory,
        // the cache wiped) — then the toggle-ON must re-stub NOW.
        kotlinx.coroutines.runBlocking { VaultSession.setScreenlockUnlockEnabled(false) }
        VaultSession.fullSessionForTest(listOf(
            ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a")))

        val msg = kotlinx.coroutines.runBlocking {
            VaultSession.setScreenlockUnlockEnabled(true)
        }

        assertTrue(msg.contains("re-stubbed now"))
        val stubs = (VaultSession.state as VaultSession.State.Unlocked).items
        assertTrue("the secrets left the memory", stubs.first().password.isEmpty())
        assertTrue("the cache holds them again", SealedVault.hasCache())
    }

    @Test
    fun toggleOnWithDeclinedGateDoesNotCrash() {
        // THE ENROLLMENT CRASH: the live gate's seal ran WITHOUT the auth
        // window (UserNotAuthenticatedException — the uncaught crash). The
        // gate must prompt first; a decline = an honest message, no seal,
        // no crash.
        SealedVault.cryptoHook = fakeCrypto()
        seedCache(ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a"))
        kotlinx.coroutines.runBlocking { VaultSession.setScreenlockUnlockEnabled(false) }
        VaultSession.fullSessionForTest(listOf(
            ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a")))
        VaultSession.sealGate = { _, _ -> false }

        val msg = kotlinx.coroutines.runBlocking {
            VaultSession.setScreenlockUnlockEnabled(true)
        }

        assertTrue(msg.contains("declined"))
        assertFalse("no seal happened", SealedVault.hasCache())
        assertTrue(VaultSession.screenlockUnlockEnabled())
    }

    @Test
    fun toggleOnWithFailingSealDoesNotCrash() {
        SealedVault.cryptoHook = fakeCrypto()
        seedCache(ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a"))
        kotlinx.coroutines.runBlocking { VaultSession.setScreenlockUnlockEnabled(false) }
        VaultSession.fullSessionForTest(listOf(
            ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a")))
        VaultSession.sealGate = { _, _ -> true }
        // The keystore refuses (the auth window closed): the seal throws.
        SealedVault.cryptoHook = object : SealedVault.SealCrypto {
            override fun seal(plain: ByteArray, aad: ByteArray): Pair<ByteArray, ByteArray> =
                throw android.security.keystore.UserNotAuthenticatedException("User not authenticated")
            override fun unseal(iv: ByteArray, ct: ByteArray, aad: ByteArray): ByteArray =
                throw android.security.keystore.UserNotAuthenticatedException("User not authenticated")
        }

        val msg = kotlinx.coroutines.runBlocking {
            VaultSession.setScreenlockUnlockEnabled(true)
        }

        assertTrue(msg.contains("the seal failed"))
        assertFalse(SealedVault.hasCache())
    }

    @Test
    fun `empty-vault promote flips the state to Unlocked`() {
        // THE UNLOCK-DOESN'T-NAVIGATE BUG: the empty-vault edge returned
        // Success WITHOUT setting the state — the session stayed Locked
        // forever (the lock screen rendered despite the successful
        // promote). The fresh-install + empty-vault path exercised it.
        kotlinx.coroutines.runBlocking { VaultSession.setScreenlockUnlockEnabled(true) }
        VaultSession.vaultFileForTest().writeText("ciphertext-blob-v1")
        // The EXISTING-but-empty cache (the device's empty-vault's shape —
        // the seal of zero items): the promote's hasCache passes, the
        // unseal returns empty → the empty-edge's path.
        val env0 = Envelope(rev = 1, deviceId = "d1")
        kotlinx.coroutines.runBlocking {
            SealedVault.sealNowAwait(emptyList(), env0, VaultSession.vaultFileForTest())
        }
        VaultSession.stubSessionForTest()   // the empty manifest's stub session

        val r = kotlinx.coroutines.runBlocking { VaultSession.promoteSealedSession() }

        assertTrue("the promote succeeds ($r)", r is VaultSession.Result.Success)
        assertTrue("THE STATE MUST BE UNLOCKED", VaultSession.state is VaultSession.State.Unlocked)
        assertTrue(VaultSession.screenlockUnlockEnabled())
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
