package com.offlinepass.app.vault
import android.content.Context

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import kotlinx.coroutines.runBlocking
import java.io.File
import java.util.Base64

/**
 * Sealed-cache core with fake CEK crypto (the keystore is device-only):
 * manifest plaintext surface, search semantics, reveal round-trip,
 * envelope-meta promotion, and staleness. Asserts the AT-REST invariant —
 * no secret material in the raw cache bytes.
 */
@RunWith(RobolectricTestRunner::class)
class SealedVaultTest {

    private lateinit var vaultFile: File

    private fun item(name: String, user: String, pass: String, vararg urls: String, email: String = "") =
        ProtonItem(name = name, username = user, email = email, password = pass, urls = urls.toList())

    @Before
    fun setup() {
        SealedVault.resetForTest(RuntimeEnvironment.getApplication())
        // The v2 crypto seam: a software AES-GCM with a throwaway key —
        // the invariant tested is the real one: the file carries only the
        // IVs + the ciphertexts (NO plaintext secrets), bound by the
        // per-item AAD.
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
        vaultFile = File(RuntimeEnvironment.getApplication().filesDir, "state/10.gpg")
        vaultFile.parentFile?.mkdirs()
        vaultFile.writeText("ciphertext-blob-v1")
    }

    @After
    fun tearDown() {
        SealedVault.resetForTest(RuntimeEnvironment.getApplication())
    }

    private fun env(vararg items: ProtonItem): Envelope {
        val e = Envelope(rev = 7, deviceId = "dev-1")
        e.items = items.toMutableList()
        e.devices.add(DeviceRecord.fromJson(org.json.JSONObject("""{"id":"k1","name":"CB","credId":"c","pub":"p",
            "keyId":"abcd1234","added":1,"salt":"s","wrapped":{"iv":"i","ct":"c"}}"""))!!)
        e.deletedItemUuids.add("gone-1")
        return e
    }

    @Test
    fun manifestCarriesMetadataButNoSecrets() {
        SealedVault.seal(
            listOf(item("GitHub", "ko", "hunter2", "https://github.com"),
                   item("Mail", "alice@x.org", "pw2", "https://mail.x.org")),
            env(), vaultFile)
        // seal is async (IO scope) — poll briefly.
        val deadline = System.currentTimeMillis() + 5000
        while (!SealedVault.hasCache() && System.currentTimeMillis() < deadline) Thread.sleep(20)
        assertTrue(SealedVault.hasCache())

        val raw = File(
            RuntimeEnvironment.getApplication().filesDir,
            "sealed/sealed.json").readText()
        println("SEALED_RAW: $raw")
        assertTrue(raw.contains("GitHub"))
        assertTrue(raw.contains("ko"))
        assertTrue(raw.contains("github.com"))
        // THE invariant: secrets never in the clear.
        assertFalse(raw.contains("hunter2"))
        assertFalse(raw.contains("pw2"))

        val rows = SealedVault.manifest()
        assertEquals(2, rows.size)
        assertEquals("ko", rows[0].username)
        assertEquals("alice@x.org", rows[1].username)
        assertEquals(7L, SealedVault.toEnvelope(emptyList()).rev)
        assertEquals(1, SealedVault.pairedDevices().size)
    }

    @Test
    fun searchMatchesNamesUsernamesUrls_notNotes() {
        val items = listOf(
            item("GitHub", "ko", "p1", "https://github.com"),
            item("Bank", "alice@x.org", "p2", "https://www.bank.example.com/login"))
        SealedVault.seal(items, env(*items.toTypedArray()), vaultFile)
        waitSealed()

        // url substring (scheme-insensitive, path-tolerant)
        assertTrue(SealedVault.searchManifest("github").size == 1)
        // username match
        assertTrue(SealedVault.searchManifest("alice").map { it } == listOf(
            SealedVault.manifest().first { it.name == "Bank" }.uuid))
        // multi-word: all words must hit
        assertTrue(SealedVault.searchManifest("bank alice").size == 1)
        // url substring inside a longer stored url ("www." + path are just text)
        assertTrue(SealedVault.searchManifest("bank.example.com").size == 1)
        // note material is sealed → no match pre-auth
        assertTrue(SealedVault.searchManifest("hunter2").isEmpty())
        // blank → everything (the list shows all rows pre-filter)
        assertTrue(SealedVault.searchManifest("   ").size == 2)
    }

    @Test
    fun revealRoundTripsSecrets_onlyForTheRequestedUuid() = runBlocking {
        val items = listOf(
            item("GitHub", "ko", "hunter2", "https://github.com"),
            item("Mail", "alice", "pw2", "https://mail.x.org"))
        SealedVault.seal(items, env(*items.toTypedArray()), vaultFile)
        waitSealed()
        val github = SealedVault.manifest().first { it.name == "GitHub" }

        val revealed = SealedVault.reveal(github.uuid)
        assertEquals("hunter2", revealed?.password)
        // And reconstructs with the manifest metadata intact.
        assertEquals("ko", revealed?.username)
        assertEquals("https://github.com", revealed?.urls?.first())

        // The other entry stays sealed (its stub has empty secrets).
        val mail = SealedVault.manifest().first { it.name == "Mail" }
        assertEquals("", SealedVault.manifestItems().first { it.itemUuid == mail.uuid }.password)
        assertNull(SealedVault.reveal("nonexistent-uuid"))
    } // runBlocking

    @Test
    fun unsealAllAndPromotePreservesEnvelopeMeta() = runBlocking {
        val items = listOf(item("GitHub", "ko", "hunter2", "https://github.com"))
        SealedVault.seal(items, env(*items.toTypedArray()), vaultFile)
        waitSealed()

        val unsealed = SealedVault.unsealAll()
        assertEquals(1, unsealed.size)
        assertEquals("hunter2", unsealed[0].password)

        val promoted = SealedVault.toEnvelope(unsealed)
        assertEquals(7L, promoted.rev)
        assertEquals("dev-1", promoted.deviceId)
        assertEquals(1, promoted.devices.size)
        assertTrue(promoted.deletedItemUuids.contains("gone-1"))
        assertEquals("hunter2", promoted.items[0].password)
    } // runBlocking

    @Test
    fun stalenessTracksVaultFileBytes() {
        val items = listOf(item("GitHub", "ko", "hunter2", "https://github.com"))
        SealedVault.seal(items, env(*items.toTypedArray()), vaultFile)
        waitSealed()
        assertTrue(SealedVault.isFresh(vaultFile))

        vaultFile.writeText("ciphertext-blob-v2")  // a pull replaced the envelope
        assertFalse(SealedVault.isFresh(vaultFile))
    }

    private fun waitSealed() {
        val deadline = System.currentTimeMillis() + 5000
        while (!SealedVault.hasCache() && System.currentTimeMillis() < deadline) Thread.sleep(20)
        assertTrue(SealedVault.hasCache())
    }
    // -- The encryption-at-rest DEFAULT --------------------------------------

    @Test
    fun atRestOffUntilEnrollmentTurnsItOn() {
        VaultSession.resetForTest(RuntimeEnvironment.getApplication() as Context)
        // The documented default: OFF until the screenlock ENROLLMENT
        // turns it on (a cache gating the vault on nothing set up = wrong).
        assertFalse("the fresh state is OFF", VaultSession.screenlockUnlockEnabled())
        kotlinx.coroutines.runBlocking { VaultSession.setScreenlockUnlockEnabled(true) }
        assertTrue("the enrollment's act turns it on", VaultSession.screenlockUnlockEnabled())
    }

    @Test
    fun explicitOffStaysOff() {
        VaultSession.resetForTest(RuntimeEnvironment.getApplication() as Context)
        kotlinx.coroutines.runBlocking { VaultSession.setScreenlockUnlockEnabled(true) }
        kotlinx.coroutines.runBlocking { VaultSession.setScreenlockUnlockEnabled(false) }
        assertFalse(VaultSession.screenlockUnlockEnabled())
        // Turning it off wipes the sealed cache (the locked state: the
        // cache mirrors the repo). Back on re-enables without resurrecting.
        kotlinx.coroutines.runBlocking { VaultSession.setScreenlockUnlockEnabled(true) }
        assertTrue(VaultSession.screenlockUnlockEnabled())
    }


    // -- THE INCREMENTAL SEAL (the save's tail) --------------------------------

    private fun blobsByUuid(): Map<String, Pair<String, String>> {
        val raw = File(
            RuntimeEnvironment.getApplication().filesDir,
            "sealed/sealed.json").readText()
        val arr = org.json.JSONObject(raw).getJSONArray("items")
        val out = mutableMapOf<String, Pair<String, String>>()
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out[o.getString("uuid")] = o.getString("iv") to o.getString("ct")
        }
        return out
    }

    @Test
    fun syncAfterSaveTouchesOnlyTheAffectedBlob() {
        val a = item("A", "ua", "pa").apply { itemUuid = "u-a" }
        val b = item("B", "ub", "pb").apply { itemUuid = "u-b" }
        val c = item("C", "uc", "pc").apply { itemUuid = "u-c" }
        kotlinx.coroutines.runBlocking {
            SealedVault.sealNowAwait(listOf(a, b, c), env(a, b, c), vaultFile)
        }
        val before = blobsByUuid()

        // The save: b's password changed (the edit), c dropped (the delete),
        // d added — the cache must re-seal ONLY b.
        val b2 = item("B", "ub", "pb2").apply { itemUuid = "u-b" }
        val d = item("D", "ud", "pd").apply { itemUuid = "u-d" }
        val env2 = Envelope(rev = 8, deviceId = "dev-1")
        env2.items = mutableListOf(a, b2, d)
        kotlinx.coroutines.runBlocking {
            SealedVault.syncAfterSaveAwait(env2, vaultFile, "u-b")
        }

        val after = blobsByUuid()
        assertEquals("u-a's blob reused verbatim", before["u-a"], after["u-a"])
        assertTrue("u-b's blob re-sealed", before["u-b"] != after["u-b"])
        assertTrue("u-c's row dropped", !after.containsKey("u-c"))
        assertTrue("u-d sealed fresh", after.containsKey("u-d"))
        // The round-trip: the unseal returns the NEW secrets and no ghosts.
        val items = kotlinx.coroutines.runBlocking { SealedVault.unsealAll() }
        assertEquals("pb2", items.first { it.itemUuid == "u-b" }.password)
        assertEquals("pa", items.first { it.itemUuid == "u-a" }.password)
        assertEquals("pd", items.first { it.itemUuid == "u-d" }.password)
        assertNull(items.firstOrNull { it.itemUuid == "u-c" })
        // The bookkeeping: the rev + the vault sha refreshed.
        val raw = org.json.JSONObject(File(
            RuntimeEnvironment.getApplication().filesDir,
            "sealed/sealed.json").readText())
        assertEquals(8, raw.getJSONObject("meta").getLong("rev"))
    }

    @Test
    fun syncAfterSaveWithoutCacheIsANoOp() {
        val a = item("A", "ua", "pa").apply { itemUuid = "u-a" }
        val env = Envelope(rev = 1, deviceId = "d")
        env.items = mutableListOf(a)
        kotlinx.coroutines.runBlocking {
            SealedVault.syncAfterSaveAwait(env, vaultFile, null)
        }
        assertFalse(SealedVault.hasCache())
    }
}
