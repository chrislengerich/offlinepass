package com.offlinepass.app.vault

import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

/**
 * THE SL LINKED-STATE IN THE STUB SESSION (the measured 0.10.8
 * regression): the fast promote's envelope carries the MANIFEST items —
 * public metadata only, the secrets sealed — and simpleLoginItem's old
 * password filter made Setup display "not linked" in every stub session
 * (and the relink would append a duplicate instead of reusing the uuid).
 * The split: simpleLoginItem() = the METADATA item (present in every
 * state); simpleLoginApiKey() = the KEY (null until a full session).
 */
@RunWith(RobolectricTestRunner::class)
class SimpleLoginStubSessionTest {

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
            return c.iv to c.doFinal(plain)
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

    private fun slItem(uuid: String = "sl-uuid-1") = ProtonItem(
        name = "SimpleLogin API",
        email = "me@passmail.net",
        password = "THE-API-KEY",
        urls = listOf("https://app.simplelogin.io"),
    ).also { it.itemUuid = uuid }

    @Test
    fun theStubSessionShowsLinkedAndKeepsTheKeyHonest() {
        seedCache(slItem())
        // The unlock shape: the stubs (the manifest metadata) in memory.
        VaultSession.stubSessionForTest()

        val meta = VaultSession.simpleLoginItem()
        assertNotNull("the linked state reads TRUE in the stub session", meta)
        assertEquals("the uuid survives (the relink reuses it)",
            "sl-uuid-1", meta?.itemUuid)
        assertEquals("the linked account's email in the metadata",
            "me@passmail.net", meta?.email)
        assertNull("the KEY is sealed in the stub session — honest null",
            VaultSession.simpleLoginApiKey())
    }

    @Test
    fun theFullSessionCarriesTheKey() {
        seedCache(slItem())
        VaultSession.fullSessionForTest(listOf(slItem()))
        assertEquals("THE-API-KEY", VaultSession.simpleLoginApiKey())
    }

    @Test
    fun noSlItemMeansNotLinked() {
        seedCache(ProtonItem(name = "A", username = "ua", password = "pa"))
        VaultSession.stubSessionForTest()
        assertNull(VaultSession.simpleLoginItem())
        assertNull(VaultSession.simpleLoginApiKey())
    }

    @Test
    fun theDomainsDisplayAndTheAliasGateWorkInTheStubSession() {
        // THE MEASURED EMPTY DOMAINS: the note carrying the domains is
        // SEALED — the stub session's display was empty and
        // isSimpleLoginAlias (the status-check button's gate) was false.
        // The domains ride the manifest's public metadata now.
        val sl = slItem().apply {
            note = "Created via offlinepass (SimpleLogin)\n" +
                "SimpleLogin alias domains: slmail.com, 8shield.net"
        }
        seedCache(sl)
        VaultSession.stubSessionForTest()

        assertEquals(setOf("slmail.com", "8shield.net"), VaultSession.simpleLoginDomains())
        assertTrue("the alias gate opens (the button appears)",
            VaultSession.isSimpleLoginAlias("x@slmail.com"))
    }

    @Test
    fun theOldCacheWithoutDomainsDegradesGracefully() {
        // The pre-domains caches: the manifest entry carries no domains —
        // the empty set, no crash; the next re-seal populates.
        val sl = slItem() // no note → no domains at seal
        seedCache(sl)
        VaultSession.stubSessionForTest()
        assertEquals(emptySet<String>(), VaultSession.simpleLoginDomains())
        org.junit.Assert.assertFalse(VaultSession.isSimpleLoginAlias("x@slmail.com"))
    }

    @Test
    fun theGatedKeyUnsealsTheSlItemInTheStubSession() = kotlinx.coroutines.runBlocking {
        seedCache(slItem())
        VaultSession.stubSessionForTest()
        assertNull("the plain accessor stays honest (sealed)",
            VaultSession.simpleLoginApiKey())
        // THE GATE STUBBED OPEN: the single unseal delivers the key.
        VaultSession.sealGate = { _, _ -> true }
        assertEquals("THE-API-KEY", VaultSession.simpleLoginKeyGated())
        // THE GATE DECLINED: null, and nothing else changed.
        VaultSession.sealGate = { _, _ -> false }
        assertNull(VaultSession.simpleLoginKeyGated())
    }
}
