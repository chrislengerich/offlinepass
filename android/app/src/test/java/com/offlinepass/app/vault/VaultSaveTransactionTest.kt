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

        override suspend fun fetchPublicKeyArmored(
            keyId: Long, requestData: android.content.Intent?
        ): OpenPgpClient.PublicKey =
            OpenPgpClient.PublicKey.Success(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"
            )

        override suspend fun trySignDetached(
            data: ByteArray, keyId: Long?, requestData: android.content.Intent?, apiVersion: Int
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

    // The vault crypto seams — captured BEFORE the injection (the object
    // statics may carry state from a previous test class) and restored in
    // @After. The fake "ciphertext" = base64 (reversible, so a decrypt
    // round-trips; the bytes still change per rev).
    private val prodEncrypt = VaultSession.vaultEncryptBytes
    private val prodDecrypt = VaultSession.vaultDecryptBytes

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
        VaultSession.vaultEncryptBytes = { plain, _, _ ->
            if (fake.encryptThrows) throw IllegalStateException("encrypt IPC died")
            if (!fake.encryptOk) throw java.io.IOException("encrypt failed")
            java.util.Base64.getEncoder().encode(plain)
        }
        VaultSession.vaultDecryptBytes = { bytes ->
            java.util.Base64.getDecoder().decode(bytes)
        }
        // Cached recipient ids → the key-lookup loop is skipped (no
        // PendingIntents under test). Local-only by default.
        VaultSession.setRecipientKeyIds(listOf(FakeOpenPgp.KEY_ID))
        VaultSession.configure(null, listOf("user@example.com"))
    }

    @After
    fun tearDown() {
        VaultSession.openPgpClientFactory = { OpenPgpClient(it) }
        VaultSession.vaultEncryptBytes = prodEncrypt
        VaultSession.vaultDecryptBytes = prodDecrypt
        VaultSession.patOverride = null
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
    fun stubSessionSaveNeverWritesEmptySecrets() = runBlocking {
        // THE STUB-INVARIANT: after a stub-mode unlock, the in-memory list
        // holds stubs (the secrets = in the sealed cache). A save must
        // promote (the batch unseal) and merge the UI's edits — encrypting
        // the stubs would WIPE every secret from the vault.
        // The seal crypto seam: a software AES (the same pattern the
        // production keystore implements).
        SealedVault.resetForTest(RuntimeEnvironment.getApplication())
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
        VaultSession.setScreenlockUnlockEnabled(true)
        // The adopt with the screenlock on = the seal + the stub conversion:
        val seeded = item("Existing").apply {
            password = "real-secret"
            note = "real-note"
        }
        VaultSession.adopt(Envelope(deviceId = "t").also { e ->
            e.rev = 3
            e.items = mutableListOf(seeded)
        })
        // The seal is async (the SealedVault scope): await it before the
        // save's promote (the production race window is human-speed; the
        // test is not).
        kotlinx.coroutines.withTimeout(5000) {
            while (!SealedVault.hasCache()) kotlinx.coroutines.delay(20)
        }
        val stateItems = (VaultSession.state as? VaultSession.State.Unlocked)?.items ?: emptyList()
        assertTrue("the session must hold stubs", stateItems.all { !it.hasSecrets() })

        // The UI's save = the stubs + the edited full item (the SAME uuid —
        // the edit flow replaces by uuid; the secrets set):
        val edited = seeded.copy(password = "changed-secret")
        val r = VaultSession.save(listOf(edited))
        assertTrue("expected Success, got $r", r is VaultSession.Result.Success)
        // The vault file must carry the REAL secrets (the base64 fake = the
        // reversible stand-in): the batch unseal's base + the edited replace.
        val plain = String(java.util.Base64.getDecoder().decode(vaultFile().readBytes()))
        assertTrue("the edited secret must be written", plain.contains("changed-secret"))
        assertFalse("the old secret must be replaced", plain.contains("real-secret"))
        assertFalse("no stubs may reach the vault", plain.contains("Existing\"}"))
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
        assertTrue("vault file updated", String(java.util.Base64.getDecoder().decode(vaultFile().readBytes())).contains("\"items\""))
        assertNotNull("commit landed in the self-healed repo", headId())
        assertEquals("pending", VaultSession.lastSaveRemoteState)
        val state = VaultSession.state as VaultSession.State.Unlocked
        assertEquals(listOf("New"), state.items.map { it.name })
    }

    @Test
    fun divergenceMergeDecryptsRemoteAndPreservesBothSides() = runBlocking {
        // THE REGRESSION TEST for the merge data-loss bug: the vault files
        // are ENCRYPTED — the merge used to feed the ciphertext to
        // Envelope.fromJson, silently merge EMPTY envelopes and wipe the
        // vault on divergence. Now the merge decrypts both sides first.
        //
        // Choreography over a real bare file:// remote:
        //   1. the local save+push (items: [Local Item])
        //   2. a "second device" clone commits its own vault ([Remote Item])
        //      and pushes → the remote and the local diverge
        //   3. syncNow → the Diverged branch → the remote decrypt →
        //      unionMerge → re-encrypt → push
        val remoteDir = File(app.cacheDir, "op-diverge-remote.git")
        remoteDir.deleteRecursively()
        org.eclipse.jgit.api.Git.init().setBare(true).setDirectory(remoteDir).call().close()
        val remoteUrl = "file://" + remoteDir.absolutePath
        VaultSession.configure(remoteUrl, listOf("user@example.com"))
        VaultSession.patOverride = "fake-pat" // ignored by the file:// transport
        seedRepo("PREVIOUS".toByteArray())

        val saved = VaultSession.save(listOf(item("Local Item")))
        assertTrue("save must succeed, got $saved", saved is VaultSession.Result.Success)
        VaultGitClient().pushBranch(remoteUrl, "fake-pat", gitRoot())

        // The second device: clone, write ITS OWN encrypted vault, commit, push.
        val second = File(app.cacheDir, "op-diverge-second")
        second.deleteRecursively()
        org.eclipse.jgit.api.Git.cloneRepository().setURI(remoteUrl).setDirectory(second).call().use { g ->
            val env = Envelope(deviceId = "second-device").also { e ->
                e.rev = 5
                e.items = mutableListOf(item("Remote Item"))
            }
            File(second, "state/10.gpg").apply { parentFile?.mkdirs() }.writeBytes(
                java.util.Base64.getEncoder()
                    .encode(env.toJsonObject().toString().toByteArray(Charsets.UTF_8)))
            g.add().addFilepattern(".").call()
            g.commit().setAuthor(PersonIdent("second", "second@test"))
                .setCommitter(PersonIdent("second", "second@test"))
                .setMessage("second device rev 5").call()
            g.push().setRemote("origin").call()
        }

        // The local head and the remote tip are siblings — syncNow's fetch
        // (by remote name, with the refspec) must see Diverged and merge.
        val r = VaultSession.syncNow()

        assertTrue("sync must succeed, got $r", r is VaultSession.Result.Success)
        val state = VaultSession.state as VaultSession.State.Unlocked
        val names = state.items.map { it.name }.sorted()
        assertTrue("both sides must survive: $names",
            names.containsAll(listOf("Local Item", "Remote Item")))

        // The pushed merged vault decodes to a JSON carrying both items.
        // (Fetch first: the push does not move the local's origin/main
        // tracking ref.)
        org.eclipse.jgit.api.Git.open(gitRoot()).use { g ->
            g.fetch().setRemote("origin").call()
        }
        val pushed = VaultGitClient().readFileAt(gitRoot(), "origin/main:state/10.gpg")
        assertNotNull("merged vault must be pushed", pushed)
        val pushedJson = String(java.util.Base64.getDecoder().decode(pushed!!))
        assertTrue(pushedJson.contains("Local Item"))
        assertTrue(pushedJson.contains("Remote Item"))
    }

    @Test
    fun remoteModeCommitLandsWithoutPatIsSuccessPending() = runBlocking {
        // Real repo so commitDirty can commit; pat() reads null under test
        // (no stored secret) → the save is durable, sync marked pending.
        VaultSession.configure("https://localhost.invalid/repo.git", listOf("user@example.com"))
        seedRepo("PREVIOUS".toByteArray())

        val r = VaultSession.save(listOf(item("New")))

        assertTrue("expected Success, got $r", r is VaultSession.Result.Success)
        assertTrue("vault file updated", String(java.util.Base64.getDecoder().decode(vaultFile().readBytes())).contains("\"items\""))
        assertNotNull("commit landed", headId())
        assertEquals("pending", VaultSession.lastSaveRemoteState)
        val state = VaultSession.state as VaultSession.State.Unlocked
        assertEquals(listOf("New"), state.items.map { it.name })
    }
}
