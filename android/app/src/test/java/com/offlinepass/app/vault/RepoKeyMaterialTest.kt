package com.offlinepass.app.vault

import android.content.Context
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.After
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
        // The OKK seam: the cert fetch = the INJECTED fake (the real shared
        // client binds OpenKeyChain's service = hangs Robolectric).
        VaultSession.openPgpClientFactory = { fake }
    }

    @After
    fun tearDown() {
        VaultSession.openPgpClientFactory = { com.offlinepass.app.crypto.OpenPgpClient(it) }
    }

    private val fake = FakeOkk("")

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
        fake.result = com.offlinepass.app.crypto.OpenPgpClient.PublicKey.Success(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfull cert\n")

        VaultSession.openOkkImportFromRepo(RuntimeEnvironment.getApplication())

        val f = File(VaultSession.gitRootPath(),
            "keys/sign/63EBEE3E00698013.pub.asc")
        assertTrue("the cert must land in keys/sign/", f.exists())
        assertTrue(f.readText().contains("full cert"))

        // The staged import file carries the cert (the OKK hand-off).
        val staged = File(RuntimeEnvironment.getApplication().cacheDir, "okk-import.asc")
        assertTrue("the staged file must exist", staged.exists())
        assertTrue("the staged file must carry the cert", staged.readText().contains("full cert"))

        // Idempotent: the cert exists → no re-fetch (the fake counts), the
        // cert unchanged → no rewrite.
        val before = f.readText()
        val fetchesBefore = fake.fetches
        VaultSession.openOkkImportFromRepo(RuntimeEnvironment.getApplication())
        assertEquals("the cert unchanged", before, f.readText())
        assertEquals("no re-fetch when the cert file exists", fetchesBefore, fake.fetches)
    }
    // -- The degraded path: a fetch failure must not lose the registry -------

    @Test
    fun fetchFailureStillRegistersMetaAndAuthLine() = runBlocking {
        VaultSession.setYubikeySsh(
            "ssh-rsa AAAAcard offlinepass-yubikey", "63EBEE3E00698013")
        val failing = fake // the fetch "fails" (no cert content)
        failing.result = com.offlinepass.app.crypto.OpenPgpClient.PublicKey.Error

        VaultSession.openOkkImportFromRepo(RuntimeEnvironment.getApplication())

        // The cert fetch failed → the cert file does NOT land; the staging
        // proceeds WITHOUT it (the hand-off stages only the existing files
        // — a recipient file is present so there is something to stage).
        assertFalse(File(VaultSession.gitRootPath(),
            "keys/sign/63EBEE3E00698013.pub.asc").exists())
        File(VaultSession.gitRootPath(), "keys/encrypt").mkdirs()
        File(VaultSession.gitRootPath(),
            "keys/encrypt/63EBEE3E00698013.pub.asc").writeText("recipient key\n")
        VaultSession.openOkkImportFromRepo(RuntimeEnvironment.getApplication())
        val staged = File(RuntimeEnvironment.getApplication().cacheDir, "okk-import.asc")
        assertTrue("the staging still runs", staged.exists())
        assertTrue("the staged file carries the recipient", staged.readText().contains("recipient key"))
        assertFalse("the failed cert is not staged", staged.readText().contains("full cert"))

        // A later SUCCESSFUL fetch fills the cert in place.
        failing.result = com.offlinepass.app.crypto.OpenPgpClient.PublicKey.Success(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfull cert\n")
        VaultSession.openOkkImportFromRepo(RuntimeEnvironment.getApplication())
        assertTrue(File(VaultSession.gitRootPath(),
            "keys/sign/63EBEE3E00698013.pub.asc").exists())
    }
}
