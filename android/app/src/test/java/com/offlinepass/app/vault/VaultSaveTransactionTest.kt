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

    /** The software seal crypto (the Robolectric-safe stand-in for the
     *  keystore AES): the same seam the SealedVault tests use. */
    private fun installSoftwareSealCrypto() {
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
    }

    @Test
    fun stubSessionSaveNeverWritesEmptySecrets() = runBlocking {
        // THE STUB-INVARIANT: after a stub-mode unlock, the in-memory list
        // holds stubs (the secrets = in the sealed cache). A save must
        // promote (the batch unseal) and merge the UI's edits — encrypting
        // the stubs would WIPE every secret from the vault.
        installSoftwareSealCrypto()
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
        // THE RE-STUB: the save's batch unseal must not leave the full
        // items in memory — the secrets return to the sealed cache.
        val after = (VaultSession.state as? VaultSession.State.Unlocked)?.items ?: emptyList()
        assertTrue("the session must re-stub after the save", after.all { !it.hasSecrets() })
    }

    @Test
    fun consecutiveStubSavesSurviveEachOther() = runBlocking {
        // THE MEASURED CLOBBER: the promote and the save-tail mutated the
        // loadedEnvelope to the STUBS (the same reference) — the next
        // save's apply-diff base was the stubs and the PREVIOUS save's
        // secrets were zeroed into the vault file. With the models
        // separated (the envelope = the full, the state = the stubs) and
        // the modifyTime resolution, consecutive edits must all survive.
        installSoftwareSealCrypto()
        VaultSession.setScreenlockUnlockEnabled(true)
        val a = item("A").apply { password = "pw-a1" }
        val b = item("B").apply { password = "pw-b0" }
        VaultSession.adopt(Envelope(deviceId = "t").also { e ->
            e.rev = 3
            e.items = mutableListOf(a, b)
        })
        kotlinx.coroutines.withTimeout(5000) {
            while (!SealedVault.hasCache()) kotlinx.coroutines.delay(20)
        }
        // Save #1: edit A → pw-a2.
        VaultSession.save(
            listOf(a.copy(password = "pw-a2")), a.itemUuid)
        // Save #2: edit B → pw-b2 (the UI's list = the stubs + the edited).
        VaultSession.save(
            listOf(b.copy(password = "pw-b2")), b.itemUuid)
        // Save #3: re-edit A → pw-a3 (the newest wins for the same uuid).
        VaultSession.save(
            listOf(a.copy(password = "pw-a3")), a.itemUuid)
        val plain = String(java.util.Base64.getDecoder().decode(vaultFile().readBytes()))
        assertTrue("save #2's edit must be written", plain.contains("pw-b2"))
        assertFalse("the pre-save stale value must be replaced", plain.contains("pw-b0"))
        assertTrue("save #3's re-edit must win for the same uuid", plain.contains("pw-a3"))
        assertFalse("the intermediate value must be replaced", plain.contains("pw-a2"))
        assertFalse("no stubs may reach the vault", plain.contains("B\"}"))
    }

    @Test
    fun seedParsesUnsignedHexIds() = runBlocking {
        // THE UNSIGNED-PARSE REGRESSION: the ids with the high bit set (the
        // card's own 0xF3E2… among them) overflow the signed Long —
        // toLongOrNull(16) returned null for EVERY real key id on-device,
        // seeding zero recipients and forcing the OKK lookup at the first
        // save. parseUnsignedLong = the bit-correct form.
        val highBitFile = "A367234D973E0E3E"      // the high bit set
        val ledgerId = "F3E2A264FA4B09AB"          // the high bit set
        gitRoot().mkdirs()
        File(gitRoot(), "keys/encrypt").mkdirs()
        File(gitRoot(), "keys/encrypt/$highBitFile.pub.asc").writeText("key 1\n")
        File(gitRoot(), "keys/encrypt/recipients.txt").writeText(
            "recipientKeyIds: 0x$ledgerId\n")
        val ids = VaultSession.seedRecipientsFromRepo()
        assertEquals(2, ids.size)
        assertTrue("the high-bit file id must parse",
            ids.contains(java.lang.Long.parseUnsignedLong(highBitFile, 16)))
        assertTrue("the high-bit ledger id must parse",
            ids.contains(java.lang.Long.parseUnsignedLong(ledgerId, 16)))
        // The persisted form = the same prefs the save reads.
        assertTrue(VaultSession.recipientKeyIds().contains(
            java.lang.Long.parseUnsignedLong(ledgerId, 16)))
        // The adoption outcome, surfaced for the Setup's status.
        assertEquals("Recipients adopted: 2 (from the vault)", VaultSession.seedStatus)
    }

    @Test
    fun seedReadsLegacyFlatLayoutAndRecentCommitsRender() = runBlocking {
        // The legacy flat layout (the pre-migration repos) + the git-log
        // display: the recentCommits = the local main's last 5, the oldest
        // last, with the sha/subject/author/age format.
        val legacyId = "A367234D973E0E3E"
        gitRoot().mkdirs()
        File(gitRoot(), "keys").mkdirs()
        File(gitRoot(), "keys/$legacyId.public.asc").writeText("legacy key\n")
        val ids = VaultSession.seedRecipientsFromRepo()
        assertTrue("the legacy flat id must parse",
            ids.contains(java.lang.Long.parseUnsignedLong(legacyId, 16)))
        assertEquals("Recipients adopted: 1 (from the vault)", VaultSession.seedStatus)

        // The commits: a real local repo with 2 commits (the 7th+ = the
        // extra one beyond the limit-5 must be dropped).
        org.eclipse.jgit.api.Git.init().setDirectory(gitRoot()).call().use { git ->
            git.repository.updateRef(org.eclipse.jgit.lib.Constants.HEAD)
                .link(org.eclipse.jgit.lib.Constants.R_HEADS + "main")
            repeat(7) { n ->
                File(gitRoot(), "state").mkdirs()
                File(gitRoot(), "state/f$n").writeText("x$n")
                git.add().addFilepattern(".").call()
                val ident = org.eclipse.jgit.lib.PersonIdent("t", "t@t")
                git.commit().setAuthor(ident).setCommitter(ident)
                    .setMessage("Update 10.gpg (rev ${n + 1})").call()
            }
        }
        val commits = VaultSession.recentCommits()
        assertEquals("the limit = 5", 5, commits.size)
        assertTrue("the newest first",
            commits.first().contains("Update 10.gpg (rev 7)"))
        assertTrue("the 5th = rev 3", commits.last().contains("Update 10.gpg (rev 3)"))
        assertTrue("the sha + the author ride along",
            commits.first().length > "Update 10.gpg (rev 7)".length &&
                commits.first().contains("t"))
    }

    @Test
    fun promoteSealedSessionEndsInStubs() = runBlocking {
        // THE STUB-INVARIANT: even the promote (the batch unseal for the
        // write ops) must not leave the full items in memory — the session
        // re-stubs (the secrets = in the sealed cache).
        installSoftwareSealCrypto()
        VaultSession.setScreenlockUnlockEnabled(true)
        val seeded = item("Existing").apply { password = "real-secret" }
        VaultSession.adopt(Envelope(deviceId = "t").also { e ->
            e.rev = 3
            e.items = mutableListOf(seeded)
        })
        kotlinx.coroutines.withTimeout(5000) {
            while (!SealedVault.hasCache()) kotlinx.coroutines.delay(20)
        }
        val r = VaultSession.promoteSealedSession()
        assertTrue("expected Success, got $r", r is VaultSession.Result.Success)
        val after = (VaultSession.state as? VaultSession.State.Unlocked)?.items ?: emptyList()
        assertTrue("the promote must end in stubs", after.all { !it.hasSecrets() })
        assertEquals("the identity fields survive", "Existing", after.firstOrNull()?.name)
    }

    @Test
    fun stubEditClearedSecretsSurviveWithEditedUuid() = runBlocking {
        // An edit that CLEARS all secrets must survive: the edited uuid
        // rides the save, so the apply-diff replaces by uuid instead of
        // letting the sealed base win over an all-empty (stub-looking) edit.
        installSoftwareSealCrypto()
        VaultSession.setScreenlockUnlockEnabled(true)
        val seeded = item("Existing").apply { password = "real-secret" }
        VaultSession.adopt(Envelope(deviceId = "t").also { e ->
            e.rev = 3
            e.items = mutableListOf(seeded)
        })
        kotlinx.coroutines.withTimeout(5000) {
            while (!SealedVault.hasCache()) kotlinx.coroutines.delay(20)
        }
        val edited = seeded.copy(password = "", note = "")
        val items = (VaultSession.state as? VaultSession.State.Unlocked)?.items
            ?.map { if (it.itemUuid == edited.itemUuid) edited else it } ?: emptyList()
        val r = VaultSession.save(items, edited.itemUuid)
        assertTrue("expected Success, got $r", r is VaultSession.Result.Success)
        val plain = String(java.util.Base64.getDecoder().decode(vaultFile().readBytes()))
        assertFalse("the cleared secret must be wiped", plain.contains("real-secret"))
        assertTrue("the item itself must remain", plain.contains("Existing"))
    }

    @Test
    fun stubAddSecretslessEntryAppendsWithUuid() = runBlocking {
        // A brand-new entry with only URLs (no secrets) must append —
        // the hasSecrets filter must not drop it when the uuid rides.
        VaultSession.setScreenlockUnlockEnabled(true)
        val added = item("UrlOnly").apply { password = "" }
        val r = VaultSession.save(listOf(added), added.itemUuid)
        assertTrue("expected Success, got $r", r is VaultSession.Result.Success)
        val plain = String(java.util.Base64.getDecoder().decode(vaultFile().readBytes()))
        assertTrue("the new entry must be in the vault", plain.contains("UrlOnly"))
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
    fun restoreAdoptsRecipientsFromVaultFilePkesks() = runBlocking {
        // THE RECIPIENT ADOPTION: the vault file carries its recipients in
        // its own PKESKs — the local-only restores have no repo ledger, so
        // the file's own record = the save targets. The fixture = a REAL
        // gpg message encrypted to TWO recipients, both ids high-bit-set
        // (the unsigned-parse = the same class as the seed's).
        val file = File(gitRoot(), "fixture-enc-two.gpg")
        gitRoot().mkdirs()
        file.writeBytes(javaClass.getResourceAsStream("/openpgp/fixture-enc-two.gpg")!!.readBytes())
        VaultSession.adoptRecipientsFromVaultFile(file)
        val ids = VaultSession.recipientKeyIds()
        assertEquals("both recipients adopted", 2, ids.size)
        assertTrue("the fixture key id adopted",
            ids.contains(java.lang.Long.parseUnsignedLong("1EA759B8783363D8", 16)))
        assertTrue("the second key id adopted",
            ids.contains(java.lang.Long.parseUnsignedLong("4199727F7793732F", 16)))
    }

    @Test
    fun backupZipRoundTripCloneSemantics() = runBlocking {
        // THE BACKUP ZIP: the export = the whole repo (the .git + the
        // worktree); the import = the clone semantics — Git.open opens a
        // REAL repository, the history is preserved, the origin is
        // stripped, and the unlock = the card path (the injected seam) →
        // the stubs. The no-plaintext invariant: the zip carries no item
        // JSON.
        installSoftwareSealCrypto()
        VaultSession.setScreenlockUnlockEnabled(true)
        val r1 = VaultSession.save(listOf(item("One").apply { password = "p1" }))
        assertTrue(r1 is VaultSession.Result.Success)
        val r2 = VaultSession.save(listOf(item("One").apply { password = "p1" },
            item("Two").apply { password = "p2" }))
        assertTrue(r2 is VaultSession.Result.Success)
        val commitsBefore = commitCount()

        val zip = File(app.cacheDir, "backup.zip")
        zip.delete()
        val n = java.io.ByteArrayOutputStream().let { bos ->
            val count = VaultSession.exportBackupZip(bos)
            bos.toByteArray().also { bytes ->
                java.util.zip.ZipInputStream(bytes.inputStream()).use { z ->
                    var e = z.nextEntry
                    while (e != null) {
                        val content = z.readBytes().toString(Charsets.ISO_8859_1)
                        assertFalse("no plaintext item JSON in the zip",
                            content.contains("Secrets") && content.contains("password\":"))
                        e = z.nextEntry
                    }
                }
                zip.writeBytes(bytes)
            }
            count
        }
        assertTrue("the zip carries the repo", n > 3)

        // The wipe + the import.
        VaultSession.zero()
        gitRoot().deleteRecursively()
        val r = VaultSession.importBackupZip(zip)
        assertTrue("expected Success, got $r", r is VaultSession.Result.Success)
        assertEquals("the history preserved (the clone)", commitsBefore, commitCount())
        // The origin stripped.
        org.eclipse.jgit.api.Git.open(gitRoot()).use { git ->
            assertNull("the origin removed (the local-only)",
                git.repository.config.getString("remote", "origin", "url"))
        }
        // The unlock = the card path (the injected seam) → the stubs.
        val items = (VaultSession.state as? VaultSession.State.Unlocked)?.items ?: emptyList()
        assertTrue("the items = the stubs after the import", items.all { !it.hasSecrets() })
        assertTrue("the items carried over", items.any { it.name == "One" })
    }

    @Test
    fun restoreDecryptUsesCardPathSeam() = runBlocking {
        // The restore's decrypt = the vaultDecryptBytes seam (the card) —
        // the OKK's decryptVerify = no longer in the path.
        val file = File(gitRoot(), "restore.gpg")
        gitRoot().mkdirs()
        val plain = """{"rev":1,"items":[{"itemUuid":"u1","name":"R"}]}"""
        file.writeBytes(java.util.Base64.getEncoder().encode(plain.toByteArray()))
        when (val r = VaultSession.decryptEnvelope(file)) {
            is VaultSession.DecryptEnvelope.Ok ->
                assertTrue("the envelope parsed", r.env.rev == 1L)
            else -> throw AssertionError("expected Ok, got $r")
        }
    }

    @Test
    fun emptyVaultCreateEnrollSaveWritesVaultAndStubs() = runBlocking {
        // THE EMPTY-VAULT EDGE: the new vault = the empty sealed cache
        // (the enroll seals zero items) bound to the not-yet-written vault
        // file — the save's promote fails on the zero items, but the save
        // must PROCEED (the vault written, the cache populated with the
        // real items, the session re-stubbed) instead of failing and
        // stranding the entries in memory (the lock lost them).
        installSoftwareSealCrypto()
        VaultSession.configure(null, emptyList())
        VaultSession.setScreenlockUnlockEnabled(true)
        VaultSession.setCommitSigningMode(VaultSession.SIGNING_SCREENLOCK)
        VaultSession.keystoreSignerHook = { "FAKE-ECDSA".toByteArray() }
        // The adopt = the EMPTY envelope (the new-vault's) — the stub
        // conversion runs (the screenlock on) → the stubSession = true,
        // the cache = sealed with the zero items.
        VaultSession.adopt(Envelope(rev = 0, deviceId = "t"))
        val stubs = (VaultSession.state as? VaultSession.State.Unlocked)?.items ?: emptyList()
        assertTrue("the stub session (the empty items)", stubs.isEmpty())
        assertEquals("the cache = sealed-empty",
            0, SealedVault.manifestItems().size)

        // The repo = git-init'd AT CREATION (the early fix): the .git
        // exists before the first save.
        VaultSession.initLocalRepo()
        assertTrue("the repo git-init'd at creation",
            File(VaultSession.gitRootPath(), ".git").exists())

        // The user's first save: the entries added in the UI (the full
        // items — the session = the empty-stub semantics).
        val entries = listOf(item("First").apply { password = "first-secret" })
        val r = VaultSession.save(entries)
        assertTrue("expected Success, got $r", r is VaultSession.Result.Success)

        // The vault file = written WITH the real secrets (the no-plaintext
        // fake = the reversible).
        val plain = String(java.util.Base64.getDecoder().decode(vaultFile().readBytes()))
        assertTrue("the secrets written", plain.contains("first-secret"))
        // The cache = populated with the real items; the session = re-stubbed.
        assertEquals("the cache populated", 1, SealedVault.manifestItems().size)
        val after = (VaultSession.state as? VaultSession.State.Unlocked)?.items ?: emptyList()
        assertTrue("the session re-stubbed", after.all { !it.hasSecrets() })
        assertEquals("the item carried", "First", after.firstOrNull()?.name)
        // The subsequent save = the normal stub flow (the promote works now).
        val r2 = VaultSession.save(listOf(
            item("First").apply { password = "first-secret" },
            item("Second").apply { password = "second-secret" }))
        assertTrue("the second save = the normal stub flow", r2 is VaultSession.Result.Success)
        val plain2 = String(java.util.Base64.getDecoder().decode(vaultFile().readBytes()))
        assertTrue(plain2.contains("second-secret"))
    }

    @Test
    fun backupImportRefusesToWipeExistingVault() = runBlocking {
        // THE GUARD: the import = a setup-time restore. An existing vault
        // must never be silently wiped by an import — the honest error
        // names the merge path, and the vault + the history survive.
        val r1 = VaultSession.save(listOf(item("Keep").apply { password = "keep-me" }))
        assertTrue(r1 is VaultSession.Result.Success)
        val beforeCommits = commitCount()
        val zip = File(app.cacheDir, "hostile-backup.zip")
        java.util.zip.ZipOutputStream(zip.outputStream()).use { z ->
            z.putNextEntry(java.util.zip.ZipEntry("state/10.gpg"))
            z.write("evil".toByteArray()); z.closeEntry()
            z.putNextEntry(java.util.zip.ZipEntry("keys/encrypt/DEAD.pub.asc"))
            z.write("x".toByteArray()); z.closeEntry()
        }
        val r = VaultSession.importBackupZip(zip)
        assertTrue("the import must refuse: $r", r is VaultSession.Result.Error)
        assertTrue("the error must name the conflict", (r as VaultSession.Result.Error).message.contains("already exists"))
        assertEquals("the history preserved", beforeCommits, commitCount())
        val plain = String(java.util.Base64.getDecoder().decode(vaultFile().readBytes()))
        assertTrue("the vault survives", plain.contains("keep-me"))
    }



    @Test
    fun backupImportRejectsZipSlipAndCorruptZips() = runBlocking {
        // The zip-slip: the "../" traversal entry = the throw + the clean.
        val slip = File(app.cacheDir, "slip.zip")
        java.util.zip.ZipOutputStream(slip.outputStream()).use { z ->
            z.putNextEntry(java.util.zip.ZipEntry("../evil.txt"))
            z.write("x".toByteArray()); z.closeEntry()
        }
        val slipResult = VaultSession.importBackupZip(slip)
        assertTrue("the zip-slip must fail: $slipResult", slipResult is VaultSession.Result.Error)
        assertFalse("nothing escapes the repo root",
            File(app.filesDir, "evil.txt").exists())

        // The corrupt zip: the garbage bytes = the clean failure.
        val corrupt = File(app.cacheDir, "corrupt.zip")
        corrupt.writeBytes("not a zip at all".toByteArray())
        val corruptResult = VaultSession.importBackupZip(corrupt)
        assertTrue("the corrupt zip must fail: $corruptResult", corruptResult is VaultSession.Result.Error)
    }



    @Test
    fun stubModeDeleteTombsTonesAndPurges() = runBlocking {
        // The delete in the stub mode: the tombstone recorded + the item
        // gone from the vault (the save's purge honors the tombstones even
        // with the stub base).
        installSoftwareSealCrypto()
        VaultSession.setScreenlockUnlockEnabled(true)
        val victim = item("Victim").apply { password = "v" }
        VaultSession.adopt(Envelope(deviceId = "t").also { e ->
            e.rev = 2
            e.items = mutableListOf(item("Keeper").apply { password = "k" }, victim)
        })
        kotlinx.coroutines.withTimeout(5000) {
            while (!SealedVault.hasCache()) kotlinx.coroutines.delay(20)
        }
        val r = VaultSession.delete(victim)
        assertTrue("expected Success, got $r", r is VaultSession.Result.Success)
        val plain = String(java.util.Base64.getDecoder().decode(vaultFile().readBytes()))
        assertFalse("the victim purged from the vault", plain.contains("Victim"))
        assertTrue("the keeper survives", plain.contains("Keeper"))
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
