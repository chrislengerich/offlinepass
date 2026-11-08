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

    override fun getSignature(data: ByteArray): ByteArray {
        var reqData: android.content.Intent? = null
        var guard = 0
        while (guard++ < 3) {
            val r = kotlinx.coroutines.runBlocking {
                client.trySignDetached(data, authSubkeyId, reqData)
            }
            when (r) {
                is OpenPgpClient.SignDetached.Ok -> {
                    return PgpSshBridge.openPgpToSshSignature(r.armored, parsed)
                }
                is OpenPgpClient.SignDetached.UserInteraction -> {
                    reqData = kotlinx.coroutines.runBlocking { interaction(r.pendingIntent) }
                        ?: throw IOException("OpenKeyChain interaction was cancelled")
                }
                is OpenPgpClient.SignDetached.Error ->
                    throw IOException("OpenKeyChain auth-subkey signing failed: ${r.message}")
            }
        }
        throw IOException("OpenKeyChain interaction aborted after retries")
    }

    override fun setPassphrase(passphrase: ByteArray?): Boolean = true
    override fun isEncrypted(): Boolean = false
    override fun clear() {}
}
