package com.offlinepass.app.crypto

import kotlinx.coroutines.runBlocking
import org.eclipse.jgit.lib.GpgConfig
import org.eclipse.jgit.lib.GpgSignature
import org.eclipse.jgit.lib.PersonIdent
import org.eclipse.jgit.lib.Repository
import org.eclipse.jgit.lib.Signer
import org.eclipse.jgit.transport.CredentialsProvider
import java.io.IOException

/**
 * JGit commit signer backed by the AndroidKeyStore screenlock key: the
 * commit payload bytes (exactly what JGit hands us — the commit object
 * minus the gpgsig header) are signed with [KeystoreSigner], gated by the
 * device's screen lock via the injected [screenlockSign] hook (which runs
 * BiometricPrompt with a CryptoObject on the UI thread).
 *
 * The embedded signature block uses a custom armor type: `git
 * verify-commit` (GPG) cannot parse it — verification goes through the
 * published public key (keys/keystore-signer.pub) and
 * scripts/verify-commit-sig.py.
 *
 * A declined screen-lock interaction (or a missing hook) throws, which
 * aborts the commit — VaultSession's transactional rollback then leaves
 * the vault untouched. Defense in depth means no unsigned slips.
 */
class KeystoreCommitSigner(
    private val screenlockSign: suspend (ByteArray) -> ByteArray?
) : Signer {

    override fun sign(
        repository: Repository?,
        config: GpgConfig?,
        content: ByteArray,
        committer: PersonIdent?,
        signingKey: String?,
        credentialsProvider: CredentialsProvider?
    ): GpgSignature {
        val der = runBlocking { screenlockSign(content) }
            ?: throw IOException("Screen-lock signature declined — commit aborted")
        val b64 = java.util.Base64.getMimeEncoder(64, "\n".toByteArray())
            .encodeToString(der)
        val armored = "-----BEGIN OFFLINEPASS SIGNATURE-----\n$b64\n" +
            "-----END OFFLINEPASS SIGNATURE-----\n"
        return GpgSignature(armored.toByteArray(Charsets.UTF_8))
    }

    override fun canLocateSigningKey(
        repository: Repository?,
        config: GpgConfig?,
        committer: PersonIdent?,
        signingKey: String?,
        credentialsProvider: CredentialsProvider?
    ): Boolean {
        // The key was generated at enrollment time; nothing to locate.
        return true
    }
}
