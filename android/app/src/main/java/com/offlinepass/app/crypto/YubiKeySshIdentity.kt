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
        // JSch negotiates the signature algorithm (preferring rsa-sha2-512
        // for RSA keys) and embeds the returned bytes verbatim. Our
        // OpenKeyChain signature is SHA-256-based: sign only when the
        // negotiated algorithm matches, else return null — JSch then
        // retries with the next algorithm in its list (rsa-sha2-256).
        val raw = openKeyChainRawSignature(data) ?: return null
        return if (algorithm == "rsa-sha2-256")
            sshString("rsa-sha2-256".toByteArray()) + sshString(raw)
        else null
    }

    override fun getSignature(data: ByteArray): ByteArray {
        val raw = openKeyChainRawSignature(data)
            ?: throw IOException("OpenKeyChain signing failed")
        return sshString("rsa-sha2-256".toByteArray()) + sshString(raw)
    }

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
    private fun openKeyChainRawSignature(data: ByteArray): ByteArray? {
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
