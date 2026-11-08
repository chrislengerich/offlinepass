package com.offlinepass.app.vault

import android.app.Application
import org.eclipse.jgit.api.Git
import org.eclipse.jgit.lib.Constants
import org.eclipse.jgit.lib.PersonIdent
import org.junit.After
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
import org.robolectric.annotation.Config
import com.offlinepass.app.crypto.OpenPgpClient
import com.offlinepass.app.crypto.OpenPgpOps
import kotlinx.coroutines.runBlocking
import java.io.File

/**
 * The save() transaction, with OpenKeyChain stubbed out (device-only IPC):
 * a [FakeOpenPgp] fakes the crypto while real JGit runs against a temp
 * repo, so the commit-boundary semantics are verified for real —
 *
 *  - a failure before the local commit lands rolls the vault file AND the
 *    in-memory session state back (first-ever saves leave no file behind);
 *  - once a commit lands the change is durable (push/PAT problems only
 *    mark the sync pending and still report Success).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class VaultSaveTransactionTest {

    /** OpenKeyChain stub: every op configurable, defaults all-succeed. */
    private class FakeOpenPgp : OpenPgpOps {
        var encryptOk = true
        var encryptThrows = false
        var signResult: OpenPgpClient.SignDetached =
            OpenPgpClient.SignDetached.Ok(FAKE_SIG)
        var lookupResult: OpenPgpClient.KeyLookup =
            OpenPgpClient.KeyLookup.Success(longArrayOf(KEY_ID))

        override suspend fun lookupKeyIds(
            userIds: Array<String>,
            requestData: android.content.Intent?
        ): OpenPgpClient.KeyLookup = lookupResult

        override suspend fun encryptTo(
            keyIds: LongArray, source: File, target: File
        ): Boolean {
            if (encryptThrows) throw IllegalStateException("encrypt IPC died")
            if (!encryptOk) return false
            // Stand-in "ciphertext": stable bytes that still change per rev
            // so the test can tell a fresh write from the previous one.
            target.writeText("ciphertext:${source.readText().hashCode()}")
            return true
        }

        override suspend fun fetchPublicKeyArmored(keyId: Long): OpenPgpClient.PublicKey =
            OpenPgpClient.PublicKey.Success(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"
            )

        override suspend fun trySignDetached(
            data: ByteArray, keyId: Long, requestData: android.content.Intent?
        ): OpenPgpClient.SignDetached = signResult

        override suspend fun pickSignKey(
            requestData: android.content.Intent?
        ): OpenPgpClient.SignKey = OpenPgpClient.SignKey.Picked(KEY_ID, "test-user")

        companion object {
            const val KEY_ID = 0x1122334455667788L
            const val FAKE_SIG =
                "-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----"
        }
    }

    private val app: Application = RuntimeEnvironment.getApplication()
    private val fake = FakeOpenPgp()

    private fun vaultFile(): File = File(File(app.filesDir, "vault/repo"), "state/10.gpg")
    private fun gitRoot(): File = File(app.filesDir, "vault/repo")

    private fun headId(): String? {
        if (!File(gitRoot(), Constants.DOT_GIT).exists()) return null
        return Git.open(gitRoot()).use { it.repository.exactRef(Constants.HEAD)?.objectId?.name }
    }

    private fun commitCount(): Int =
        Git.open(gitRoot()).use { git ->
            var n = 0
            git.log().call().forEach { n++ }
            n
        }

    /** Seeds the repo with one commit carrying [bytes] at state/10.gpg. */
    private fun seedRepo(bytes: ByteArray): String {
        gitRoot().mkdirs()
        Git.init().setDirectory(gitRoot()).call().use { git ->
            git.repository.updateRef(Constants.HEAD).link(Constants.R_HEADS + "main")
        }
        vaultFile().apply { parentFile?.mkdirs() }.writeBytes(bytes)
        Git.open(gitRoot()).use { git ->
            git.add().addFilepattern(".").call()
            val ident = PersonIdent("test", "test@test")
            git.commit().setAuthor(ident).setCommitter(ident).setMessage("seed").call()
        }
        return headId()!!
    }

    private fun item(name: String = "Example") = ProtonItem(
        name = name, username = "user", urls = listOf("https://example.com")
    )

    @Before
    fun setUp() {
        File(app.filesDir, "vault").deleteRecursively()
        VaultSession.resetForTest(app)
        VaultSession.openPgpClientFactory = { fake }
        // Cached recipient ids → the key-lookup loop is skipped (no
        // PendingIntents under test). Local-only by default.
        VaultSession.setRecipientKeyIds(listOf(FakeOpenPgp.KEY_ID))
        VaultSession.configure(null, listOf("user@example.com"))
    }

    @After
    fun tearDown() {
        VaultSession.openPgpClientFactory = { OpenPgpClient(it) }
    }

    // -- success ------------------------------------------------------------

    @Test
    fun localOnlySaveCommitsAndUpdatesSession() = runBlocking {
        val r = VaultSession.save(listOf(item("Site A")))
        assertTrue("expected Success, got $r", r is VaultSession.Result.Success)
        assertTrue(vaultFile().exists())
        assertNotNull("local commit must land", headId())
        assertEquals(1, commitCount())
        val state = VaultSession.state as VaultSession.State.Unlocked
        assertEquals(listOf("Site A"), state.items.map { it.name })
        assertEquals("none", VaultSession.lastSaveRemoteState)
    }

    @Test
    fun secondSaveBumpsRevAndCommit() = runBlocking {
        VaultSession.save(listOf(item("A")))
        val head1 = headId()
        VaultSession.save(listOf(item("A"), item("B")))
        val head2 = headId()
        assertTrue(head1 != head2)
        assertEquals(2, commitCount())
        assertEquals(2L, VaultSession.currentRev())
    }

    // -- screenlock commit signing (exclusive of the OKK signing path) -------

    @Test
    fun screenlockModeSignsCommitWithoutOkkInteraction() = runBlocking {
        // Screenlock signing is EXCLUSIVE of the OpenKeyChain signing path:
        // no signingKeyId is set here, and the save must not require any
        // OpenKeyChain interaction. The fake hook stands in for the
        // BiometricPrompt + Keystore flow.
        VaultSession.configure(null, listOf("user@example.com"))
        VaultSession.setRecipientKeyIds(listOf(FakeOpenPgp.KEY_ID))
        seedRepo("PREVIOUS".toByteArray())
        VaultSession.setCommitSigningMode(VaultSession.SIGNING_SCREENLOCK)
        var hookCalls = 0
        VaultSession.keystoreSignerHook = { bytes ->
            hookCalls++
            assertTrue("hook receives the commit payload bytes", bytes.isNotEmpty())
            "FAKE-ECDSA".toByteArray()
        }

        val r = VaultSession.save(listOf(item("Signed")))

        assertTrue("expected Success, got $r", r is VaultSession.Result.Success)
        assertEquals(1, hookCalls)
        assertNotNull("commit landed", headId())
        // The commit object carries the custom armor block (the embedded
        // screenlock signature over the commit payload).
        Git.open(gitRoot()).use { git ->
            val head = git.repository.exactRef(org.eclipse.jgit.lib.Constants.HEAD)!!
            val text = String(git.repository.open(head.objectId).getBytes())
            assertTrue(
                "commit must embed the screenlock signature armor",
                text.contains("BEGIN OFFLINEPASS SIGNATURE"))
            // The armor carries the base64 of the (fake) signature bytes.
            assertTrue(
                "armor must contain the base64 signature",
                text.contains("RkFLRS1FQ0RTQQ=="))
        }
    }

    @Test
    fun screenlockDeclinedRollsBack() = runBlocking {
        VaultSession.configure(null, listOf("user@example.com"))
        VaultSession.setRecipientKeyIds(listOf(FakeOpenPgp.KEY_ID))
        val seedHead = seedRepo("PREVIOUS".toByteArray())
        VaultSession.setCommitSigningMode(VaultSession.SIGNING_SCREENLOCK)
        VaultSession.keystoreSignerHook = { null } // user declines the screen lock

        val r = VaultSession.save(listOf(item("Declined")))

        assertTrue("expected Error, got $r", r is VaultSession.Result.Error)
        assertEquals("PREVIOUS", vaultFile().readText())
        assertEquals("HEAD must not move", seedHead, headId())
        assertFalse(VaultSession.state is VaultSession.State.Unlocked)
    }

    // -- pre-commit failure: rollback ----------------------------------------

    @Test
    fun signPreflightFailureRollsBackFileAndState() = runBlocking {
        val head = seedRepo("PREVIOUS".toByteArray())
        fake.signResult = OpenPgpClient.SignDetached.Error("sign key locked")

        val r = VaultSession.save(listOf(item("New")))

        assertTrue(r is VaultSession.Result.Error)
        assertTrue("message should say nothing was saved: ${r}",
            (r as VaultSession.Result.Error).message.contains("nothing saved"))
        assertEquals("vault file restored byte-for-byte",
            "PREVIOUS", vaultFile().readText())
        assertEquals("HEAD must not move", head, headId())
        assertEquals("commit count unchanged", 1, commitCount())
        assertEquals("rev restored", 0L, VaultSession.currentRev())
        assertTrue(VaultSession.syncStatus?.contains("rolled back") == true)
        assertFalse(VaultSession.state is VaultSession.State.Unlocked)
    }

    @Test
    fun encryptFailureRollsBackFile() = runBlocking {
        seedRepo("PREVIOUS".toByteArray())
        fake.encryptOk = false

        val r = VaultSession.save(listOf(item("New")))

        assertTrue(r is VaultSession.Result.Error)
        assertEquals("PREVIOUS", vaultFile().readText())
        assertFalse(VaultSession.state is VaultSession.State.Unlocked)
    }

    @Test
    fun encryptExceptionRollsBack() = runBlocking {
        seedRepo("PREVIOUS".toByteArray())
        fake.encryptThrows = true

        val r = VaultSession.save(listOf(item("New")))

        assertTrue(r is VaultSession.Result.Error)
        assertEquals("PREVIOUS", vaultFile().readText())
        assertFalse(VaultSession.state is VaultSession.State.Unlocked)
    }

    @Test
    fun firstEverSaveFailureLeavesNoVaultFile() = runBlocking {
        fake.signResult = OpenPgpClient.SignDetached.Error("sign key locked")

        val r = VaultSession.save(listOf(item("New")))

        assertTrue(r is VaultSession.Result.Error)
        assertFalse("no vault file may survive a failed first save", vaultFile().exists())
        assertNull("repo has no commits", headId())
        assertFalse(VaultSession.state is VaultSession.State.Unlocked)
    }

    // -- post-commit durability ----------------------------------------------

    @Test
    fun remoteModeMissingRepoSelfHealsAndSavesLocally() = runBlocking {
        // Remote configured but the repo was never cloned (failed setup):
        // the save must still be durable — init a local repo, commit, and
        // leave the push pending. The remote never gates a save.
        VaultSession.configure("https://localhost.invalid/repo.git", listOf("user@example.com"))
        seedRepo("PREVIOUS".toByteArray())
        File(gitRoot(), ".git").deleteRecursively() // no repo — the failed-clone state

        val r = VaultSession.save(listOf(item("New")))

        assertTrue("expected Success (self-healed), got $r", r is VaultSession.Result.Success)
        assertTrue("vault file updated", vaultFile().readText().startsWith("ciphertext:"))
        assertNotNull("commit landed in the self-healed repo", headId())
        assertEquals("pending", VaultSession.lastSaveRemoteState)
        val state = VaultSession.state as VaultSession.State.Unlocked
        assertEquals(listOf("New"), state.items.map { it.name })
    }

    @Test
    fun remoteModeCommitLandsWithoutPatIsSuccessPending() = runBlocking {
        // Real repo so commitDirty can commit; pat() reads null under test
        // (no stored secret) → the save is durable, sync marked pending.
        VaultSession.configure("https://localhost.invalid/repo.git", listOf("user@example.com"))
        seedRepo("PREVIOUS".toByteArray())

        val r = VaultSession.save(listOf(item("New")))

        assertTrue("expected Success, got $r", r is VaultSession.Result.Success)
        assertTrue("vault file updated", vaultFile().readText().startsWith("ciphertext:"))
        assertNotNull("commit landed", headId())
        assertEquals("pending", VaultSession.lastSaveRemoteState)
        val state = VaultSession.state as VaultSession.State.Unlocked
        assertEquals(listOf("New"), state.items.map { it.name })
    }
}
