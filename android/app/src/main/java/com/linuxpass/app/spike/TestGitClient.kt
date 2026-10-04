package com.linuxpass.app.spike

import android.util.Log
import org.eclipse.jgit.api.Git
import org.eclipse.jgit.lib.Constants
import org.eclipse.jgit.lib.PersonIdent
import org.eclipse.jgit.transport.RefSpec
import org.eclipse.jgit.transport.TagOpt
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider
import java.io.File

/**
 * Spike S3: the vault repo's git transport, trimmed from offlinecam's
 * proven GitClient (attribution: same JGit-on-Android shapes — clone-else-
 * fetch, "Nothing to fetch." tolerance, stale index.lock cleanup,
 * empty-repo branch handling, token-as-password credentials, push-result
 * reading). HTTPS + fine-grained PAT; SSH (Keystore key / CCID) is a
 * later upgrade.
 */
class TestGitClient {

    private class TokenCredentials(pat: String) : UsernamePasswordCredentialsProvider(
        // GitHub wants any username: the token is the password.
        "x-access-token", pat
    )

    fun open(remote: String, pat: String, root: File, branch: String = "main"): File {
        root.parentFile?.mkdirs()
        if (File(root, Constants.DOT_GIT).exists()) {
            Git.open(root).use { git ->
                // A remote with no refs yet (first device in an empty repo)
                // is the normal first-use state, not a failure.
                runCatching {
                    git.fetch()
                        .setRemote(remote)
                        .setCredentialsProvider(TokenCredentials(pat))
                        .setTagOpt(TagOpt.NO_TAGS)
                        .call()
                }.onFailure { error ->
                    if (error.message != "Nothing to fetch.") throw error
                }
            }
        } else {
            Log.i(TAG, "Cloning $remote into ${root.name}")
            Git.cloneRepository()
                .setURI(remote)
                .setDirectory(root)
                .setCredentialsProvider(TokenCredentials(pat))
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

    fun commitAndPush(
        remote: String,
        pat: String,
        root: File,
        message: String,
        branch: String = "main"
    ): String? {
        open(remote, pat, root, branch)
        Git.open(root).use { git ->
            git.add().addFilepattern(".").call()
            if (!git.status().call().isClean) {
                val ident = PersonIdent("linuxpass-android", "linuxpass@android.local")
                git.commit().setAuthor(ident).setCommitter(ident).setMessage(message).call()
            } else {
                Log.i(TAG, "Tree clean: pushing any locally-committed-but-unpushed head")
            }
            val results = git.push()
                .setRemote(remote)
                .setRefSpecs(RefSpec("refs/heads/$branch:refs/heads/$branch"))
                .setCredentialsProvider(TokenCredentials(pat))
                .call()
            for (result in results) for (u in result.remoteUpdates) {
                Log.i(TAG, "push ${u.remoteName}: ${u.status} ${u.message ?: ""}")
            }
            val head = git.repository.exactRef(Constants.HEAD)?.objectId?.name?.take(7)
            Log.i(TAG, "Pushed $head as '$message'")
            return head
        }
    }

    /**
     * The clone ends on whatever HEAD the server advertised — for an empty
     * repo an unborn branch. Retarget HEAD to the wanted branch so the
     * first commit roots it (lifted from offlinecam).
     */
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
        private const val TAG = "S3"
    }
}
