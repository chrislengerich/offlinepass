package com.offlinepass.app.vault

import org.eclipse.jgit.api.Git
import org.eclipse.jgit.lib.Constants
import org.eclipse.jgit.lib.GpgConfig
import org.eclipse.jgit.lib.GpgSignature
import org.eclipse.jgit.lib.PersonIdent
import org.eclipse.jgit.lib.Repository
import org.eclipse.jgit.lib.Signer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.Rule
import java.io.File

/**
 * The vault repo's git-state logic (work-plan T3): [VaultGitClient]'s
 * ahead/behind divergence accounting (the Setup sync line's data —
 * da0fcff), the reset warning's states, and the dirty-commit helper.
 * Real local repos on the plain JVM (JGit needs no device); the network
 * paths are NOT covered here (L3, androidTest).
 */
class VaultGitClientTest {

    @get:Rule
    val tmp = org.junit.rules.TemporaryFolder()

    private val client = VaultGitClient()

    /** A local repo with `count` commits on main, each touching a distinct
     *  file (the vault's state/ shape). Returns the repo root. */
    private fun repoWith(count: Int): File {
        val root = tmp.newFolder("repo")
        client.gitInit(root)
        repeat(count) { i ->
            File(root, "state").mkdirs()
            File(root, "state/$i.txt").writeText("rev $i")
            client.commitFile(root, "rev $i", null)
        }
        return root
    }

    /** Points origin/<branch> at a given commit id (the remote-tracking
     *  ref = the state of the last fetch — aheadBehind's input). */
    private fun setRemoteTracking(root: File, commitId: String, branch: String = "main") {
        Git.open(root).use { git ->
            val update = git.repository.refDatabase
                .newUpdate(Constants.R_REMOTES + "origin/" + branch, false)
            update.setNewObjectId(org.eclipse.jgit.lib.ObjectId.fromString(commitId))
            update.update()
        }
    }

    private fun headId(root: File): String =
        Git.open(root).use { it.repository.resolve(Constants.R_HEADS + "main")!!.name }

    // -- aheadBehind --------------------------------------------------------

    @Test
    fun `no repo - null`() {
        assertNull(client.aheadBehind(tmp.newFolder("empty")))
    }

    @Test
    fun `no remote-tracking ref (local-only) - null`() {
        val root = repoWith(2)
        assertNull(client.aheadBehind(root))
    }

    @Test
    fun `head equals remote - in sync (0, 0)`() {
        val root = repoWith(2)
        setRemoteTracking(root, headId(root))
        assertEquals(0 to 0, client.aheadBehind(root))
    }

    @Test
    fun `local ahead of the remote-tracking ref - (n, 0)`() {
        val root = repoWith(3)
        // The remote saw only the first commit; two local commits unpushed.
        val first = Git.open(root).use { git ->
            git.log().call().toList().reversed().first().name
        }
        setRemoteTracking(root, first)
        assertEquals(2 to 0, client.aheadBehind(root))
    }

    @Test
    fun `local behind the remote-tracking ref - (0, n)`() {
        val root = repoWith(1)
        // The remote (tracking ref) is at a LATER commit the clone lacks:
        // a peer's commit built ON TOP of our head, known to us only as
        // the fetched tracking ref (HEAD itself does not move).
        val peerId = Git.open(root).use { git ->
            val inserter = git.repository.newObjectInserter()
            val build = org.eclipse.jgit.lib.CommitBuilder()
            build.author = PersonIdent("peer", "p@x")
            build.committer = PersonIdent("peer", "p@x")
            build.message = "peer rev"
            build.setParentId(org.eclipse.jgit.lib.ObjectId.fromString(headId(root)))
            build.setTreeId(git.repository.resolve(Constants.R_HEADS + "main^{tree}")!!)
            val id = inserter.insert(build).toObjectId()
            inserter.flush()
            inserter.close()
            id.name
        }
        setRemoteTracking(root, peerId)
        assertEquals(0 to 1, client.aheadBehind(root))
    }

    @Test
    fun `diverged - (a, b)`() {
        val root = repoWith(1)
        val baseId = headId(root)
        // Local moves on.
        File(root, "state/local.txt").writeText("local")
        client.commitFile(root, "local rev", null)
        // The remote moved from the same base (a peer device's push): a
        // raw CommitBuilder commit with parent = base, different tree.
        val peerId = Git.open(root).use { git ->
            val inserter = git.repository.newObjectInserter()
            val build = org.eclipse.jgit.lib.CommitBuilder()
            build.author = PersonIdent("peer", "p@x")
            build.committer = PersonIdent("peer", "p@x")
            build.message = "peer rev"
            build.setParentId(org.eclipse.jgit.lib.ObjectId.fromString(baseId))
            build.setTreeId(
                git.repository.resolve(Constants.R_HEADS + "main^{tree}")!!)
            val id = inserter.insert(build).toObjectId()
            inserter.flush()
            inserter.close()
            id.name
        }
        setRemoteTracking(root, peerId)
        assertEquals(1 to 1, client.aheadBehind(root))
    }

    // -- commitDirty ----------------------------------------------------------

    @Test
    fun `commitDirty on a clean tree - null (no commit)`() {
        val root = repoWith(1)
        val before = headId(root)
        assertNull(client.commitDirty(root, "should not commit"))
        assertEquals(before, headId(root))
    }

    @Test
    fun `commitDirty on a dirty tree - commits and returns the head`() {
        val root = repoWith(1)
        File(root, "state/new.txt").writeText("stranded")
        val head = client.commitDirty(root, "stranded file committed")
        assertNotNull(head)
        assertEquals(head, headId(root).take(7))
    }

    @Test
    fun `commitDirty with a signer embeds the gpgsig header`() {
        val root = repoWith(1)
        File(root, "state/new.txt").writeText("signed")
        client.commitDirty(root, "signed commit", object : Signer {
            override fun sign(
                repository: Repository?,
                config: GpgConfig?,
                content: ByteArray,
                committer: PersonIdent?,
                signingKey: String?,
                credentialsProvider: org.eclipse.jgit.transport.CredentialsProvider?
            ): GpgSignature = GpgSignature(
                "-----BEGIN PGP SIGNATURE-----\nwnUEAAE\n=ab\n-----END PGP SIGNATURE-----"
                    .toByteArray())

            override fun canLocateSigningKey(
                repository: Repository?,
                config: GpgConfig?,
                committer: PersonIdent?,
                signingKey: String?,
                credentialsProvider: org.eclipse.jgit.transport.CredentialsProvider?
            ): Boolean = true
        })
        val raw = Git.open(root).use { git ->
            String(git.log().call().first().rawBuffer, Charsets.ISO_8859_1)
        }
        assertTrue("the commit must carry a gpgsig header",
            raw.contains("gpgsig"))
    }

    // -- gitInit / remote helpers --------------------------------------------

    @Test
    fun `gitInit points HEAD at main (not master)`() {
        val root = tmp.newFolder("init")
        client.gitInit(root)
        Git.open(root).use { git ->
            assertEquals(Constants.R_HEADS + "main",
                git.repository.fullBranch)
        }
    }

    @Test
    fun `gitInit is idempotent (no re-init, no history loss)`() {
        val root = repoWith(1)
        val before = headId(root)
        client.gitInit(root)
        assertEquals(before, headId(root))
        assertTrue(File(root, Constants.DOT_GIT).exists())
    }

    @Test
    fun `remoteBranchExists false before any tracking ref, true after`() {
        val root = repoWith(1)
        assertFalse(client.remoteBranchExists(root))
        setRemoteTracking(root, headId(root))
        assertTrue(client.remoteBranchExists(root))
    }
}
