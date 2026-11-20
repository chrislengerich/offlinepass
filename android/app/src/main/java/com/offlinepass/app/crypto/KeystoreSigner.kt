package com.offlinepass.app.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * The screenlock commit signer: an AndroidKeyStore EC key that cannot
 * leave the device and requires the screen lock (biometric or device
 * credential) for EVERY signature. This is the ALTERNATIVE to the
 * OpenKeyChain commit signer — enrolling it means commits are authorized
 * by this device's screen lock and the OpenKeyChain signing interaction
 * is not used at all.
 *
 * The public half is published into the repo (keys/keystore-signer.pub)
 * so any client can verify revisions without access to this device. The
 * private half is per-device: a newly enrolled device publishes its own
 * key (git history keeps the old ones for verifying older revisions).
 */
object KeystoreSigner {
    const val ALIAS = "offlinepass-commit-signer"
    const val PUB_FILE_NAME = "keystore-signer.pub"

    fun hasKey(): Boolean = runCatching {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .containsAlias(ALIAS)
    }.getOrDefault(false)

    /** Deletes the signing key — the un-enroll migration's last step
     *  (auth and signing must not rely on it afterwards). */
    fun removeKey() {
        runCatching {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
        }
    }

    /** Generates the signing key (idempotent). Per-operation auth: every
     *  signature needs a fresh screen-lock interaction. */
    fun ensureKey() {
        if (hasKey()) return
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
        if (Build.VERSION.SDK_INT >= 30) {
            // Biometric OR device credential, per operation.
            spec.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
            )
        } else {
            // Per-operation (validity -1); pre-30 crypto auth is
            // biometric-strong only — the device-credential fallback for
            // crypto ops arrives with API 30.
            spec.setUserAuthenticationValidityDurationSeconds(-1)
        }
        gen.initialize(spec.build())
        gen.generateKeyPair()
    }

    /** Public key as SPKI PEM — verification needs no auth, on any device. */
    fun publicKeyPem(): String {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val cert = ks.getCertificate(ALIAS)
            ?: throw IllegalStateException("Keystore signer key not generated yet")
        val b64 = Base64.getMimeEncoder(64, "\n".toByteArray())
            .encodeToString(cert.publicKey.encoded)
        return "-----BEGIN PUBLIC KEY-----\n$b64\n-----END PUBLIC KEY-----\n"
    }

    /** The public key as an OpenSSH line (ecdsa-sha2-nistp256) — the form
     *  GitHub takes; used for the repo's authorized-keys registry. */
    fun publicKeySshLine(comment: String): String? = runCatching {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val pub = ks.getCertificate(ALIAS).publicKey
            as java.security.interfaces.ECPublicKey
        fun sshString(b: ByteArray): ByteArray {
            val out = ByteArray(4 + b.size)
            out[0] = ((b.size ushr 24) and 0xFF).toByte()
            out[1] = ((b.size ushr 16) and 0xFF).toByte()
            out[2] = ((b.size ushr 8) and 0xFF).toByte()
            out[3] = (b.size and 0xFF).toByte()
            b.copyInto(out, 4)
            return out
        }
        // The uncompressed point: 0x04 || X || Y (fixed 32-byte halves).
        fun fixed32(v: java.math.BigInteger): ByteArray {
            val raw = v.toByteArray()
            val stripped = if (raw.size > 1 && raw[0] == 0.toByte()) raw.copyOfRange(1, raw.size) else raw
            return ByteArray(32 - stripped.size) + stripped
        }
        val point = byteArrayOf(4) + fixed32(pub.w.affineX) + fixed32(pub.w.affineY)
        val curve = "nistp256".toByteArray()
        val blob = sshString("ecdsa-sha2-nistp256".toByteArray()) +
            sshString(curve) + sshString(point)
        "ecdsa-sha2-nistp256 " + java.util.Base64.getEncoder().encodeToString(blob) +
            " " + comment
    }.getOrNull()

    /** Short identifier for UI display (first 16 hex of the SPKI hash). */
    fun publicKeyFingerprint(): String = runCatching {
        val t0 = android.os.SystemClock.elapsedRealtime()
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val fp = "%064x".format(java.math.BigInteger(1, digest.digest(ks.getCertificate(ALIAS).publicKey.encoded)))
            .take(16)
        android.util.Log.i("SetupTiming", "keyFingerprint=${android.os.SystemClock.elapsedRealtime() - t0}ms")
        fp
    }.getOrDefault("(not generated)")

    /** Prepares a signature over [bytes]. With per-operation auth the
     *  caller presents this Signature to BiometricPrompt as a CryptoObject
     *  and completes with [finish] after authentication. */
    fun prepare(bytes: ByteArray): Signature {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = ks.getEntry(ALIAS, null) as KeyStore.PrivateKeyEntry
        return Signature.getInstance("SHA256withECDSA").apply {
            initSign(entry.privateKey)
            update(bytes)
        }
    }

    /** Completes the signature — only succeeds once the screen-lock
     *  interaction has authorized this exact operation. */
    fun finish(signature: Signature): ByteArray = signature.sign()
}
