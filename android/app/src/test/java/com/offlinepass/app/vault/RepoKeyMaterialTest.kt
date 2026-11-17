package com.offlinepass.app.vault

import android.content.Context
import kotlinx.coroutines.runBlocking
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
 * The repo key-material update (the card's cert materialization + the
 * meta registry) with a STUBBED OpenKeyChain client: the fetch returns a
 * canned armored cert, the files land in keys/sign/, the meta entry
 * appears, and re-runs are idempotent.
 */
@RunWith(RobolectricTestRunner::class)
class RepoKeyMaterialTest {

    @Before
    fun setUp() {
        VaultSession.resetForTest(RuntimeEnvironment.getApplication() as Context)
    }

    private class FakeOkk(private val armored: String) :
        com.offlinepass.app.crypto.OpenPgpOps {
        var fetches = 0
        var result: com.offlinepass.app.crypto.OpenPgpClient.PublicKey? = null
        override suspend fun lookupKeyIds(
            userIds: Array<String>, requestData: android.content.Intent?
        ) = throw UnsupportedOperationException()
        override suspend fun encryptTo(
            keyIds: LongArray, source: File, target: File
        ) = throw UnsupportedOperationException()
        override suspend fun fetchPublicKeyArmored(
            keyId: Long, requestData: android.content.Intent?
        ): com.offlinepass.app.crypto.OpenPgpClient.PublicKey {
            fetches += 1
            return result ?: com.offlinepass.app.crypto.OpenPgpClient.PublicKey.Success(armored)
        }
        override suspend fun pickSignKey(requestData: android.content.Intent?)
            : com.offlinepass.app.crypto.OpenPgpClient.SignKey =
            throw UnsupportedOperationException()
        override suspend fun trySignDetached(
            data: ByteArray, keyId: Long?,
            requestData: android.content.Intent?, apiVersion: Int
        ): com.offlinepass.app.crypto.OpenPgpClient.SignDetached =
            throw UnsupportedOperationException()
    }

    @Test
    fun cardCertLandsInSignFolderAndMetaRegistry() = runBlocking {
        VaultSession.setYubikeySsh(
            "ssh-rsa AAAAcard offlinepass-yubikey", "63EBEE3E00698013")
        VaultSession.setDeviceName("Pixel 8")
        val fake = FakeOkk("-----BEGIN PGP PUBLIC KEY BLOCK-----\nfull cert\n")

        VaultSession.updateRepoKeyMaterial(fake)

        val f = File(VaultSession.gitRootPath(),
            "keys/sign/63EBEE3E00698013.pub.asc")
        assertTrue("the cert must land in keys/sign/", f.exists())
        assertTrue(f.readText().contains("full cert"))
        val entries = VaultSession.readDeviceRegistry()
        assertEquals(1, entries.size)
        // The card entry carries the CARD's identity — the cardholder name
        // when readable, else the neutral fallback — never the device name.
        assertEquals("Security key 8013", entries[0].name)
        assertEquals("keys/sign/63EBEE3E00698013.pub.asc", entries[0].cert)
        assertTrue(entries[0].authKey!!.contains("offlinepass-yubikey"))
        val auth = File(VaultSession.gitRootPath(), "keys/auth/authorized-keys")
        assertTrue(auth.exists() && auth.readText().contains("offlinepass-yubikey"))

        // Idempotent: the cert unchanged → no rewrite; the meta entry stays.
        val before = f.readText()
        VaultSession.updateRepoKeyMaterial(fake)
        assertEquals(before, f.readText())
        assertEquals(1, VaultSession.readDeviceRegistry().size)
    }
    // -- The degraded path: a fetch failure must not lose the registry -------

    @Test
    fun fetchFailureStillRegistersMetaAndAuthLine() = runBlocking {
        VaultSession.setYubikeySsh(
            "ssh-rsa AAAAcard offlinepass-yubikey", "63EBEE3E00698013")
        val failing = FakeOkk("") // the fetch "fails" (no cert content)
        failing.result = com.offlinepass.app.crypto.OpenPgpClient.PublicKey.Error

        VaultSession.updateRepoKeyMaterial(failing)

        // The meta entry exists but its cert file does NOT (a dangling ref
        // until a later fetch succeeds — the hand-off only stages existing
        // files, so this is safe).
        val entries = VaultSession.readDeviceRegistry()
        assertEquals(1, entries.size)
        assertEquals("keys/sign/63EBEE3E00698013.pub.asc", entries[0].cert)
        assertFalse(File(VaultSession.gitRootPath(),
            "keys/sign/63EBEE3E00698013.pub.asc").exists())
        assertTrue(File(VaultSession.gitRootPath(), "keys/auth/authorized-keys")
            .readText().contains("offlinepass-yubikey"))

        // A later SUCCESSFUL fetch fills the cert in place.
        failing.result = com.offlinepass.app.crypto.OpenPgpClient.PublicKey.Success(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfull cert\n")
        VaultSession.updateRepoKeyMaterial(failing)
        assertTrue(File(VaultSession.gitRootPath(),
            "keys/sign/63EBEE3E00698013.pub.asc").exists())
    }
}
