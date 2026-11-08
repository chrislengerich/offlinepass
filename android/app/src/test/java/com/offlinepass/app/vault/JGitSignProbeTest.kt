package com.offlinepass.app.vault

import org.eclipse.jgit.api.Git
import org.eclipse.jgit.lib.Constants
import org.eclipse.jgit.lib.GpgConfig
import org.eclipse.jgit.lib.GpgSignature
import org.eclipse.jgit.lib.PersonIdent
import org.eclipse.jgit.lib.Repository
import org.eclipse.jgit.lib.Signer
import org.eclipse.jgit.transport.CredentialsProvider
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Probe: does JGit 7.7.1 actually call a pluggable [Signer] and embed the
 * returned signature as the commit's `gpgsig` header? Mirrors the exact
 * CommitCommand usage of [VaultGitClient.commitFile]/commitDirty — this
 * isolates JGit behavior from OpenKeyChain (device-only).
 */
class JGitSignProbeTest {

    private class StubSigner : Signer {
        var signCalls = 0
        override fun sign(
            repository: Repository?,
            config: GpgConfig?,
            content: ByteArray,
            committer: PersonIdent?,
            signingKey: String?,
            credentialsProvider: CredentialsProvider?
        ): GpgSignature {
            signCalls++
            // A syntactically plausible armored OpenPGP signature; content
            // doesn't matter — only whether JGit embeds it.
            val armored = "-----BEGIN PGP SIGNATURE-----\n" +
                "wnUEAAEKCa0AAAAwQCoAAAAAAAAA\n" +
                "=abcd\n" +
                "-----END PGP SIGNATURE-----"
            return GpgSignature(armored.toByteArray(Charsets.UTF_8))
        }

        override fun canLocateSigningKey(
            repository: Repository?,
            config: GpgConfig?,
            committer: PersonIdent?,
            signingKey: String?,
            credentialsProvider: CredentialsProvider?
        ): Boolean = true
    }

    @Test
    fun commitWithCustomSignerEmbedsGpgsig() {
        val dir = File.createTempFile("jgit-sign-probe", "").apply {
            delete(); mkdirs()
        }
        val git = Git.init().setDirectory(dir).call()
        File(dir, "f.txt").writeText("x")
        git.add().addFilepattern(".").call()
        val signer = StubSigner()
        val ident = PersonIdent("offlinepass-android", "offlinepass@android.local")
        git.commit()
            .setAuthor(ident).setCommitter(ident)
            .setMessage("signed probe")
            .setSign(true).setSigner(signer)
            .call()

        assertTrue("signer was never invoked", signer.signCalls > 0)
        val head = git.repository.exactRef(Constants.HEAD)!!.objectId!!
        val raw = String(git.repository.open(head, Constants.OBJ_COMMIT).bytes)
        assertTrue("commit has no gpgsig header:\n$raw", raw.contains("gpgsig"))
    }
}
