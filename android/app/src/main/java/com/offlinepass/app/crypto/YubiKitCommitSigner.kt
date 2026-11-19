package com.offlinepass.app.crypto

import org.eclipse.jgit.lib.GpgConfig
import org.eclipse.jgit.lib.GpgSignature
import org.eclipse.jgit.lib.PersonIdent
import org.eclipse.jgit.lib.Repository
import org.eclipse.jgit.lib.Signer
import org.eclipse.jgit.transport.CredentialsProvider
import java.io.IOException

/**
 * JGit commit signer backed by the YubiKey's SIGNATURE slot via YubiKit —
 * the same measured-green path the SSH auth uses: the commit payload bytes
 * (exactly what JGit hands us — the commit object minus the gpgsig header)
 * are hashed with SHA-256, the bare DigestInfo goes to the card's PSO:CDS
 * (the card pads on-device), and the raw signature is wrapped into a v4
 * OpenPGP detached-signature packet (PgpSigBuilder) and armored.
 *
 * The result verifies with standard gpg/GitHub: the enrolled S subkey's
 * public key is part of the GPG key blob published on GitHub, so signed
 * commits show up as Verified.
 *
 * UX: the card's SIGNATURE slot touch policy applies per signature — the
 * key's LED blinks and wants a finger for EVERY commit. The PIN comes
 * through the shared app-level cache ([prompt]) and is remembered ONLY on
 * success ([rememberPin]) — a wrong PIN re-prompts with the
 * attempts-remaining message instead of poisoning the session.
 */
class YubiKitCommitSigner(
    private val context: android.content.Context,
    private val keyId: Long,
    private val prompt: suspend () -> CharArray?,
    private val rememberPin: (CharArray) -> Unit = {},
    /** Injectable for tests: the card op (the real one is YubiKitSshAuth). */
    private val cardSign: suspend (pin: CharArray, payload: ByteArray) -> ByteArray =
        { pin, payload -> YubiKitSshAuth.sign(context, pin, payload) },
) : Signer {

    override fun sign(
        repository: Repository?,
        config: GpgConfig?,
        content: ByteArray,
        committer: PersonIdent?,
        signingKey: String?,
        credentialsProvider: CredentialsProvider?
    ): GpgSignature {
        val armored = kotlinx.coroutines.runBlocking {
            val pin = prompt()
                ?: throw IOException("OpenPGP PIN cancelled — commit aborted")
            // The sig packet's body = the KEY TYPE's (one unauthenticated
            // read): RSA = the one-MPI padded block; EC = the r/s MPIs
            // from the card's DER. Unknown = RSA (the legacy default).
            val pubkeyAlg = runCatching {
                if (YubiKitSshAuth.slotKeyType(context) == "EC")
                    PgpSigBuilder.PUB_ALG_ECDSA else PgpSigBuilder.PUB_ALG_RSA
            }.getOrDefault(PgpSigBuilder.PUB_ALG_RSA)
            val packet = try {
                // The v4 hash (content+trailer) and the packet share the
                // same prefix by construction; the card signs the hash's
                // DigestInfo (RSA pads it on-device; EC signs the raw
                // digest — sign() strips it by the slot's key type).
                PgpSigBuilder.detachedSignature(
                    content, keyId,
                    createdAt = (System.currentTimeMillis() / 1000).toInt(),
                    sign = { digestInfo ->
                        kotlinx.coroutines.runBlocking { cardSign(pin, digestInfo) }
                    },
                    pubkeyAlg = pubkeyAlg)
            } catch (e: Exception) {
                throw IOException("YubiKey commit signing: ${e.message}", e)
            }
            rememberPin(pin)
            PgpSigBuilder.armoredSignature(packet)
        }
        return GpgSignature(armored.toByteArray(Charsets.UTF_8))
    }

    override fun canLocateSigningKey(
        repository: Repository?,
        config: GpgConfig?,
        committer: PersonIdent?,
        signingKey: String?,
        credentialsProvider: CredentialsProvider?
    ): Boolean {
        // The key id comes from the YubiKey SSH enrollment (the SIGNATURE
        // slot's subkey); nothing to locate.
        return true
    }
}
