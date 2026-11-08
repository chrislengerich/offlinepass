package com.offlinepass.app.vault

import android.util.Log
import org.eclipse.jgit.api.Git
import org.eclipse.jgit.lib.Constants
import org.eclipse.jgit.lib.ObjectId
import org.eclipse.jgit.lib.PersonIdent
import org.eclipse.jgit.lib.Repository
import org.eclipse.jgit.revwalk.RevWalk
import org.eclipse.jgit.transport.RefSpec
import org.eclipse.jgit.transport.TagOpt
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider
import java.io.File

/**
 * The vault repo's git transport, lifted from offlinecam's proven GitClient
 * (clone-else-fetch, "Nothing to fetch." tolerance, stale index.lock
 * cleanup, empty-repo branch handling, token-as-password credentials) and
 * extended with the divergence machinery the vault layer needs: ancestor
 * checks between the local and remote heads, blob reads at a ref, hard
 * reset to the remote, and pushes that THROW on rejection (callers — never
 * report a rejected push as success).
 */
class VaultGitClient {

    private class TokenCredentials(pat: String) : UsernamePasswordCredentialsProvider(
        // GitHub wants any username: the token is the password.
        "x-access-token", pat
    )

    /** Where the local head stands relative to origin/<branch>. */
    sealed class Divergence {
        object UpToDate : Divergence()
        /** Local has commits the remote lacks: a push is a fast-forward. */
        data class AheadOnly(val headId: String) : Divergence()
        /** Remote has commits we lack: pull/decrypt to advance. */
        data class BehindOnly(val remoteId: String) : Divergence()
        /** Both sides moved: application-level merge required. */
        data class Diverged(val headId: String, val remoteId: String) : Divergence()
    }

    /** SSH-form remote (git@host:path or ssh://...)? The JSch/Keystore
     *  identity authenticates; PAT credentials are HTTPS-only. */
    fun isSshRemote(remote: String): Boolean =
        remote.startsWith("git@") || remote.startsWith("ssh://")

    init {
        // JGit 7 has no bundled JSch transport; register ours once so SSH
        // remotes ride the Keystore-gated identity.
        com.offlinepass.app.crypto.KeystoreSshSessionFactory.register()
    }

    fun open(remote: String, pat: String, root: File, branch: String = "main"): File {
        root.parentFile?.mkdirs()
        if (File(root, Constants.DOT_GIT).exists()) {
            Git.open(root).use { git ->
                // A local-only repo gaining a remote for the first time:
                // connect origin (the history merges via syncNow's
                // divergence handling).
                if (git.repository.config.getString("remote", "origin", "url") == null) {
                    git.remoteAdd().setName("origin").setUri(org.eclipse.jgit.transport.URIish(remote)).call()
                    Log.i(TAG, "connected local repo to origin")
                }
                // A remote with no refs yet (first device in an empty repo)
                // is the normal first-use state, not a failure.
                runCatching {
                    git.fetch()
                        .setRemote(remote)
                        .also { if (!isSshRemote(remote)) it.setCredentialsProvider(TokenCredentials(pat)) }
                        .setTagOpt(TagOpt.NO_TAGS)
                        .setTimeout(30)
                        .call()
                }.onFailure { error ->
                    // Offline is fine: local commits must still work; the
                    // push retries when connectivity returns.
                    if (error.message != "Nothing to fetch.") {
                        Log.w(TAG, "fetch failed (continuing offline): ${error.message}")
                    }
                }
            }
        } else {
            // Stale debris (a previous clone failed mid-write) would make the
            // clone fail with "destination path exists and is not empty".
            if (root.exists()) root.deleteRecursively()
            Log.i(TAG, "Cloning $remote into ${root.name}")
            Git.cloneRepository()
                .setURI(remote)
                .setDirectory(root)
                .also { if (!isSshRemote(remote)) it.setCredentialsProvider(TokenCredentials(pat)) }
                .setTimeout(30)
                .call()
                .close()
        }
        ensureBranch(root, branch)
        // A lock left behind by a process that died mid-add blocks every add
        // after it; only this process writes this clone.
        val indexLock = File(root, "index.lock")
        if (indexLock.exists() && indexLock.delete()) {
            Log.w(TAG, "Removed a stale index lock")
        }
        return root
    }

    fun headVsRemote(root: File, branch: String = "main"): Divergence {
        Git.open(root).use { git ->
            val repo = git.repository
            val headId = repo.resolve(Constants.HEAD) ?: return Divergence.BehindOnly(
                repo.resolve(remoteRef(branch))?.name ?: return Divergence.UpToDate
            )
            val remoteId = repo.resolve(remoteRef(branch))
                ?: return Divergence.AheadOnly(headId.name) // empty remote
            if (headId.name == remoteId.name) return Divergence.UpToDate

            RevWalk(repo).use { walk ->
                walk.isRetainBody = true
                val head = walk.parseCommit(headId)
                val remote = walk.parseCommit(remoteId)
                var remoteReachableFromHead = false
                val walk2 = RevWalk(repo)
                walk2.markStart(walk2.parseCommit(headId))
                var c = walk2.next()
                while (c != null) {
                    if (c.name == remoteId.name) { remoteReachableFromHead = true; break }
                    c = walk2.next()
                }
                walk2.dispose()
                Log.i(TAG, "headVsRemote head=${headId.name.take(7)} remote=${remoteId.name.take(7)} remoteInHead=$remoteReachableFromHead")
                return when {
                    remoteReachableFromHead -> Divergence.AheadOnly(headId.name)
                    walk.isMergedInto(remote, head) -> Divergence.BehindOnly(remoteId.name)
                    else -> Divergence.Diverged(headId.name, remoteId.name)
                }
            }
        }
    }

    private fun remoteRef(branch: String) = Constants.R_REMOTES + "origin/" + branch

    /** Bytes of [path] at [ref] (e.g. "origin/main:state/10.gpg"), or null. */
    fun readFileAt(root: File, refPath: String): ByteArray? {
        Git.open(root).use { git ->
            val id = git.repository.resolve(refPath) ?: return null
            return git.repository.open(id).bytes
        }
    }

    /** Hard reset the working tree + branch to the given ref. */
    fun resetHardTo(root: File, refName: String) {
        Git.open(root).use { git ->
            git.reset().setMode(org.eclipse.jgit.api.ResetCommand.ResetType.HARD)
                .setRef(refName).call()
        }
    }

    /** Stages everything and commits (signing via [signer] when present). */
    fun commitFile(root: File, message: String, signer: org.eclipse.jgit.lib.Signer?): String {
        Git.open(root).use { git ->
            git.add().addFilepattern(".").call()
            val ident = PersonIdent("offlinepass-android", "offlinepass@android.local")
            val cmd = git.commit().setAuthor(ident).setCommitter(ident).setMessage(message)
            if (signer != null) cmd.setSign(true).setSigner(signer)
            cmd.call()
            return git.repository.exactRef(Constants.HEAD)?.objectId?.name?.take(7) ?: ""
        }
    }

    /** Inits a LOCAL git repo (local-only vaults: history without a remote). */
    fun gitInit(root: File, branch: String = "main"): File {
        if (!File(root, Constants.DOT_GIT).exists()) {
            root.mkdirs()
            Git.init().setDirectory(root).call().use { git ->
                // Point HEAD at the wanted branch (init defaults to master).
                git.repository.updateRef(Constants.HEAD).link(Constants.R_HEADS + branch)
            }
            Log.i(TAG, "Initialized local git repo at ${root.name}")
        }
        return root
    }

    /** Pushes the branch; THROWS (does not swallow) on rejection. */
    /** True when the remote (origin) already carries [branch] — i.e. the
     *  remote repo is NOT empty/first-push. */
    fun remoteBranchExists(root: File, branch: String = "main"): Boolean =
        Git.open(root).use { git ->
            git.repository.exactRef(org.eclipse.jgit.lib.Constants.R_REMOTES + "origin/" + branch) != null
        }

    fun pushBranch(remote: String, pat: String, root: File, branch: String = "main") {
        Git.open(root).use { git ->
            val results = git.push()
                .setRemote(remote)
                .setRefSpecs(RefSpec("refs/heads/$branch:refs/heads/$branch"))
                .also { if (!isSshRemote(remote)) it.setCredentialsProvider(TokenCredentials(pat)) }
                .setTimeout(30)
                .call()
            for (result in results) for (u in result.remoteUpdates) {
                Log.i(TAG, "push ${u.remoteName}: ${u.status} ${u.message ?: ""}")
                if (u.status != org.eclipse.jgit.transport.RemoteRefUpdate.Status.OK &&
                    u.status != org.eclipse.jgit.transport.RemoteRefUpdate.Status.UP_TO_DATE
                ) throw org.eclipse.jgit.api.errors.TransportException(
                    "push rejected: ${u.status} ${u.message ?: ""}"
                )
            }
        }
    }

    /** Commits the working tree when dirty (used before sync so stranded
     * vault files get committed + pushed). Returns the new head, or null
     * when the tree was already clean. */
    fun commitDirty(root: File, message: String, signer: org.eclipse.jgit.lib.Signer? = null): String? {
        Git.open(root).use { git ->
            git.add().addFilepattern(".").call()
            if (git.status().call().isClean) return null
            val ident = PersonIdent("offlinepass-android", "offlinepass@android.local")
            val cmd = git.commit().setAuthor(ident).setCommitter(ident).setMessage(message)
            if (signer != null) cmd.setSign(true).setSigner(signer)
            cmd.call()
            return git.repository.exactRef(Constants.HEAD)?.objectId?.name?.take(7)
        }
    }

    /** Convenience (spikes/simple callers): open → add-all → commit (with a
     * signed→unsigned fallback when a signer is given) → push. The push
     * THROWS on rejection; the commit never reports a rejected push as
     * success. */
    fun commitAndPush(
        remote: String,
        pat: String,
        root: File,
        message: String,
        branch: String = "main",
        signer: org.eclipse.jgit.lib.Signer? = null
    ): String? {
        open(remote, pat, root, branch)
        Git.open(root).use { git ->
            git.add().addFilepattern(".").call()
            val ident = PersonIdent("offlinepass-android", "offlinepass@android.local")
            if (!git.status().call().isClean) {
                val cmd = git.commit().setAuthor(ident).setCommitter(ident).setMessage(message)
                if (signer != null) cmd.setSign(true).setSigner(signer)
                try {
                    cmd.call()
                } catch (e: Exception) {
                    if (signer == null) throw e
                    // Signing failed (e.g. the key cannot sign): retry unsigned.
                    Log.w(TAG, "signed commit failed: ${e.message} — retrying unsigned", e)
                    git.commit().setAuthor(ident).setCommitter(ident).setMessage(message).call()
                }
            } else {
                Log.i(TAG, "Tree clean: pushing any locally-committed-but-unpushed head")
            }
            pushBranch(remote, pat, root, branch)
            return git.repository.exactRef(Constants.HEAD)?.objectId?.name?.take(7)
        }
    }

    private fun ensureBranch(root: File, branch: String) {
        val git = Git.open(root)
        git.use { repo ->
            val wanted = Constants.R_HEADS + branch
            if (repo.repository.fullBranch == wanted) return

            if (repo.repository.exactRef(wanted) != null) {
                repo.checkout().setName(branch).call()
                return
            }
            val remoteRef = repo.repository.exactRef(Constants.R_REMOTES + "origin/" + branch)
            if (remoteRef != null) {
                repo.checkout().setCreateBranch(true).setName(branch).setStartPoint(remoteRef.name).call()
                return
            }
            if (repo.repository.resolve(Constants.HEAD) == null) {
                repo.repository.updateRef(Constants.HEAD).link(wanted)
            } else {
                repo.checkout().setCreateBranch(true).setName(branch).setStartPoint(Constants.HEAD).call()
            }
        }
    }

    companion object {
        private const val TAG = "Git"
    }
}
