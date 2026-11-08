package com.offlinepass.app.crypto

import com.jcraft.jsch.Identity
import java.io.IOException

/**
 * SSH identity backed by the YubiKey's OpenPGP AUTH subkey via
 * OpenKeyChain's remote API: the handshake blob goes to OpenKeyChain's
 * detached-sign action (keyId = the auth subkey), the returned OpenPGP
 * signature packet is bridged to an SSH signature (PgpSshBridge), and the
 * YubiKey touch happens inside the OpenKeyChain interaction.
 *
 * The public half is the OpenSSH line ALREADY enrolled in GitHub (the
 * same one desktop gpg-agent pushes with) — provided at setup.
 */
class YubiKeySshIdentity(
    private val client: OpenPgpClient,
    private val authSubkeyId: Long,
    private val publicKeyLine: String,
    private val interaction: suspend (android.app.PendingIntent) -> android.content.Intent?
) : Identity {

    private val parsed = PgpSshBridge.parsePublicKeyLine(publicKeyLine)

    override fun getAlgName(): String = parsed.algorithm
    override fun getName(): String = "offlinepass-yubikey"
    override fun getPublicKeyBlob(): ByteArray = parsed.wireBlob

    override fun getSignature(data: ByteArray, algorithm: String): ByteArray? {
        // JSch negotiates the algorithm and embeds our returned bytes
        // verbatim — so the blob's INNER algorithm name must match the
        // signature's ACTUAL hash (from the PGP packet), not JSch's
        // preference. A correctly self-labeled rsa-sha2-* blob is accepted
        // by GitHub regardless of which name JSch asked for.
        val sig = openKeyChainSig(data) ?: return null
        android.util.Log.i("YubiKeySsh",
            "ssh sig: jsch asked=$algorithm, labeled=" + sig.sigName)
        return sig.wire
    }

    override fun getSignature(data: ByteArray): ByteArray {
        val sig = openKeyChainSig(data)
            ?: throw IOException("OpenKeyChain signing failed")
        return sig.wire
    }

    private fun openKeyChainSig(data: ByteArray): WireSig? {
        val raw = openKeyChainRawSignature(data) ?: return null
        val sigName = try {
            PgpSshBridge.rsaSigNameForHash(raw.hashAlg)
        } catch (e: PgpSshBridge.PgpSshBridgeException) {
            android.util.Log.w("YubiKeySsh", "unsupported PGP hash: ${raw.hashAlg}")
            return null
        }
        return WireSig(sigName, sshString(sigName.toByteArray()) + sshString(raw.bytes))
    }
    private data class WireSig(val sigName: String, val wire: ByteArray)

    private fun sshString(b: ByteArray): ByteArray {
        val out = ByteArray(4 + b.size)
        out[0] = ((b.size ushr 24) and 0xFF).toByte()
        out[1] = ((b.size ushr 16) and 0xFF).toByte()
        out[2] = ((b.size ushr 8) and 0xFF).toByte()
        out[3] = (b.size and 0xFF).toByte()
        b.copyInto(out, 4)
        return out
    }

    /** Signs [data] with the auth subkey via OpenKeyChain (handling the
     *  interaction loop) and returns the RAW signature bytes extracted
     *  from the OpenPGP packet. */
    private fun openKeyChainRawSignature(data: ByteArray): PgpSshBridge.RawSig? {
        var reqData: android.content.Intent? = null
        var guard = 0
        while (guard++ < 3) {
            val r = kotlinx.coroutines.runBlocking {
                client.trySignDetached(data, authSubkeyId, reqData)
            }
            when (r) {
                is OpenPgpClient.SignDetached.Ok ->
                    return try {
                        PgpSshBridge.extractRawSignature(r.armored, parsed.algorithm)
                    } catch (e: PgpSshBridge.PgpSshBridgeException) {
                        android.util.Log.w("YubiKeySsh", "pgp→ssh bridge: ${e.message}")
                        null
                    }
                is OpenPgpClient.SignDetached.UserInteraction -> {
                    reqData = kotlinx.coroutines.runBlocking { interaction(r.pendingIntent) }
                        ?: return null
                }
                is OpenPgpClient.SignDetached.Error -> {
                    android.util.Log.w("YubiKeySsh", "OKK sign failed: ${r.message}")
                    return null
                }
            }
        }
        return null
    }

    override fun setPassphrase(passphrase: ByteArray?): Boolean = true
    override fun isEncrypted(): Boolean = false
    override fun clear() {}
}
