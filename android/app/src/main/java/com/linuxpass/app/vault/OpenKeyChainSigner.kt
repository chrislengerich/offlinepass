package com.linuxpass.app.vault

import com.linuxpass.app.crypto.OpenPgpClient
import kotlinx.coroutines.runBlocking
import org.eclipse.jgit.api.errors.CanceledException
import org.eclipse.jgit.api.errors.UnsupportedSigningFormatException
import org.eclipse.jgit.lib.GpgConfig
import org.eclipse.jgit.lib.GpgSignature
import org.eclipse.jgit.lib.PersonIdent
import org.eclipse.jgit.lib.Repository
import org.eclipse.jgit.lib.Signer
import org.eclipse.jgit.transport.CredentialsProvider
import java.io.IOException

/**
 * JGit commit signer backed by OpenKeyChain: the commit payload bytes go to
 * OpenKeyChain's DETACHED_SIGN (armored PGP signature over the exact bytes,
 * which is what git's gpgsig header carries), so desktop `git log
 * --show-signature` verifies against the same identity that receives the
 * vault.
 *
 * The private material never leaves its key store — OpenKeyChain (and any
 * hardware token behind it) does the signing.
 */
class OpenKeyChainSigner(
    private val client: OpenPgpClient,
    private val keyId: Long
) : Signer {

    override fun sign(
        repository: Repository?,
        config: GpgConfig?,
        content: ByteArray,
        committer: PersonIdent?,
        signingKey: String?,
        credentialsProvider: CredentialsProvider?
    ): GpgSignature {
        val armored = runBlocking {
            client.signDetached(content, keyId)
        } ?: throw IOException("OpenKeyChain detached signing failed (key 0x%016X)".format(keyId))
        return GpgSignature(armored.toByteArray(Charsets.UTF_8))
    }

    override fun canLocateSigningKey(
        repository: Repository?,
        config: GpgConfig?,
        committer: PersonIdent?,
        signingKey: String?,
        credentialsProvider: CredentialsProvider?
    ): Boolean {
        // The key id was resolved during save() before this signer is used.
        return true
    }
}
