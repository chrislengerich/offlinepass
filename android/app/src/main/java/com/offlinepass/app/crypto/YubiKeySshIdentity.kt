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
    private val interaction: suspend (android.app.PendingIntent) -> android.content.Intent?,
    /** When non-null: the YubiKit backend (the card's SIGNATURE slot) —
     *  bypasses OpenKeyChain entirely. */
    private val yubiKitSigner: (suspend (payload: ByteArray) -> ByteArray)? = null
) : Identity {

    companion object {
        /** The LAST signing failure's OpenKeyChain-side message, surfaced
         *  through the sync/load error string — JSch's bare "Auth
         *  cancelled" hides exactly what this records. */
        @Volatile var lastAuthError: String? = null
    }

    private val parsed = PgpSshBridge.parsePublicKeyLine(publicKeyLine)

    override fun getAlgName(): String = parsed.algorithm
    override fun getName(): String = "offlinepass-yubikey"
    override fun getPublicKeyBlob(): ByteArray = parsed.wireBlob

    override fun getSignature(data: ByteArray, algorithm: String): ByteArray? {
        // The YubiKit backend: the card's SIGNATURE slot signs the PKCS#1
        // DigestInfo directly — no OpenKeyChain, works for card-resident
        // keys. The PIN arrives via the hook (once per identity session).
        if (yubiKitSigner != null) {
            return try {
                val payload = com.offlinepass.app.crypto.SshRsaPkcs1
                    .pkcs1SignBlock(algorithm, data, com.offlinepass.app.crypto.PgpSshBridge.rsaModulusSize(parsed.wireBlob))
                val raw = kotlinx.coroutines.runBlocking { yubiKitSigner?.invoke(payload) }
                    ?: run {
                        lastAuthError = "OpenPGP PIN cancelled"
                        return null
                    }
                android.util.Log.i("YubiKeySsh", "yubikit sig: alg=$algorithm, ${raw.size} bytes")
                sshString(algorithm.toByteArray()) + sshString(raw)
            } catch (e: Exception) {
                android.util.Log.w("YubiKeySsh", "yubikit sign failed: ${e.message}")
                lastAuthError = e.message
                return null
            }
        }
        // JSch negotiates the algorithm (rsa-sha2-512 first for RSA keys)
        // and embeds the returned bytes verbatim. The blob's INNER algorithm
        // name must match the signature's ACTUAL hash (from the PGP
        // packet): SHA-256 -> rsa-sha2-256, SHA-512 -> rsa-sha2-512. On a
        // mismatch return null so JSch retries with the next algorithm.
        val sig = openKeyChainSig(data) ?: return null
        if (sig.sigName != algorithm) {
            android.util.Log.i("YubiKeySsh",
                "alg mismatch: jsch asked=$algorithm, ours=" + sig.sigName + " - retrying")
            lastAuthError = "OpenKeyChain signed with ${sig.sigName} but the SSH handshake asked $algorithm"
            return null
        }
        android.util.Log.i("YubiKeySsh", "ssh sig offered: alg=" + sig.sigName)
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
        lastAuthError = null
        while (guard++ < 3) {
            val r = kotlinx.coroutines.runBlocking {
                client.trySignDetached(data, authSubkeyId, reqData)
            }
            when (r) {
                is OpenPgpClient.SignDetached.Ok ->
                    return try {
                        // parsed carries the REAL modulus (the enrolled
                        // line's blob) — the RSA signature pads to IT.
                        PgpSshBridge.extractRawSignature(r.armored, parsed)
                    } catch (e: PgpSshBridge.PgpSshBridgeException) {
                        android.util.Log.w("YubiKeySsh", "pgp→ssh bridge: ${e.message}")
                        lastAuthError = "signature bridge: ${e.message}"
                        null
                    }
                is OpenPgpClient.SignDetached.UserInteraction -> {
                    reqData = kotlinx.coroutines.runBlocking { interaction(r.pendingIntent) }
                    if (reqData == null) {
                        lastAuthError = "OpenKeyChain interaction cancelled"
                        return null
                    }
                }
                is OpenPgpClient.SignDetached.Error -> {
                    android.util.Log.w("YubiKeySsh", "OKK sign failed: ${r.message}")
                    // Name the subkey so a wrong-id enrollment is obvious in
                    // the surfaced error (the picker can hand back the
                    // primary, which carries no signing capability).
                    lastAuthError = "OpenKeyChain: ${r.message} (key 0x" +
                        "%016X".format(authSubkeyId) + ")"
                    return null
                }
            }
        }
        lastAuthError = "OpenKeyChain signing retries exhausted"
        return null
    }

    override fun setPassphrase(passphrase: ByteArray?): Boolean = true
    override fun isEncrypted(): Boolean = false
    override fun clear() {}
}
