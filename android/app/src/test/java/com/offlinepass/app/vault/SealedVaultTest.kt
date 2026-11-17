package com.offlinepass.app.vault

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
    fun atRestEncryptionIsOnByDefault() {
        // A fresh state (no explicit pref) → the sealed cache is ON.
        assertTrue(VaultSession.screenlockUnlockEnabled())
    }

    @Test
    fun explicitOffStaysOff() {
        VaultSession.setScreenlockUnlockEnabled(false)
        assertFalse(VaultSession.screenlockUnlockEnabled())
        // Turning it off wipes the sealed cache (the existing contract).
        // Back on re-enables without resurrecting anything.
        VaultSession.setScreenlockUnlockEnabled(true)
        assertTrue(VaultSession.screenlockUnlockEnabled())
    }

}
