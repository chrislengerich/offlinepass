package com.offlinepass.app.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.util.Base64

/**
 * The app's per-device git identity: an SSH keypair whose private half is
 * generated and held non-exportably inside Android Keystore (the phone's
 * TEE), never touching the vault's own key material.
 *
 * Algorithm: ed25519 where the device's Keystore supports it (API 33+ /
 * KeyMint 3.0), RSA-3072 fallback (PKCS#1 v1.5 + SHA-256, so the SSH
 * signature lands as rsa-sha2-256, the modern minimum GitHub accepts).
 *
 * [ensureKeyPair] is idempotent; the public half exports in OpenSSH wire
 * format for GitHub deploy-key enrollment.
 */
class SshKeyManager(
    private val provider: String = "AndroidKeyStore",
    private val alias: String = "offlinepass-git"
) {

    data class PublicKeyInfo(
        val algorithm: String,
        val publicKey: PublicKey,
        /** The SSH wire blob: string(alg) + string(components). */
        val wireBlob: ByteArray,
        /** Full OpenSSH public-key line, ready for a GitHub deploy key. */
        val openSshLine: String,
        /** ssh-keygen-style fingerprint of the wire blob: "SHA256:<b64>". */
        val fingerprint: String
    )

    fun ensureKeyPair(): PublicKeyInfo {
        val ks = load()
        if (ks.containsAlias(alias)) {
            val alg = ks.getCertificate(alias).publicKey.algorithm
            if (alg != "RSA") {
                // This device's Keystore silently substitutes an EC key when
                // "Ed25519" is requested — unusable for ssh-rsa-family auth;
                // purge and regenerate as RSA.
                ks.deleteEntry(alias)
                android.util.Log.w(TAG, "deleted unsupported '$alg' key under alias")
            } else if (!isScreenlockGated(ks)) {
                // A pre-screenlock key (spike-era) has no user-auth
                // constraint: its signatures would work without the device
                // screen lock. Purge and regenerate gated.
                ks.deleteEntry(alias)
                android.util.Log.w(TAG, "purged non-screenlock-gated key; regenerating")
            }
        }
        if (!ks.containsAlias(alias)) generate(ks)
        val pub = ks.getCertificate(alias).publicKey
        android.util.Log.i(TAG, "publicKey algorithm=${pub.algorithm}, encoded=${pub.encoded.size}B")
        val wire = wireBlob(pub)
        val alg = keyTypeName(pub)
        val comment = "offlinepass-android-${android.os.Build.MODEL?.replace(" ", "-")}"
        // ssh-keygen-format fingerprint: "SHA256:" + unpadded base64 of the
        // blob's SHA-256 — lets the receiver prove the QR-decoded key is
        // byte-identical to what this device generated.
        val fp = "SHA256:" + Base64.getEncoder().withoutPadding()
            .encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(wire))
        android.util.Log.i(TAG, "identity fingerprint: $fp")
        return PublicKeyInfo(pub.algorithm, pub, wire, "$alg ${Base64.getEncoder().encodeToString(wire)} $comment", fp)
    }

    fun hasKeyPair(): Boolean = runCatching { load().containsAlias(alias) }.getOrDefault(false)

    /** True when the enrolled key requires user authentication (the
     *  screenlock gate); a pre-gating key is purged and regenerated. */
    private fun isScreenlockGated(ks: KeyStore): Boolean = runCatching {
        val priv = ks.getKey(alias, null) as PrivateKey
        // ONLY the AndroidKeyStore KeyFactory can handle its own keys —
        // the default provider's cannot (and throwing here would purge a
        // good key on every call, churning the git identity).
        val ki = java.security.KeyFactory.getInstance(priv.algorithm, provider)
            .getKeySpec(priv, android.security.keystore.KeyInfo::class.java)
                as android.security.keystore.KeyInfo
        val gated = ki.isUserAuthenticationRequired
        android.util.Log.i(TAG, "screenlock gate check: gated=$gated, " +
            "validity=${ki.userAuthenticationValidityDurationSeconds}s")
        gated
    }.getOrElse { e ->
        // A check failure must NEVER purge the key: the deployed GitHub
        // deploy key would stop matching. Assume gated and continue.
        android.util.Log.w(TAG, "screenlock gate check failed (keeping key): ${e.message}")
        true
    }

    fun keyAlgorithm(): String {
        val pub = load().getCertificate(alias).publicKey
        return pub.algorithm
    }

    /** A fresh Signature instance with an EXPLICIT JCE algorithm — used by
     *  the SSH identity to match the negotiated rsa-sha2-256/512 hash. */
    fun newSignerFor(jceAlgorithm: String): Signature {
        val priv = load().getKey(alias, null) as PrivateKey
        return Signature.getInstance(jceAlgorithm).apply { initSign(priv) }
    }

    /** A fresh Signature instance over the Keystore private key. */
    fun newSigner(): Signature {
        val priv = load().getKey(alias, null) as PrivateKey
        val alg = load().getCertificate(alias).publicKey.algorithm
        val sig = when (alg) {
            "Ed25519" -> try {
                Signature.getInstance("NONEwithEd25519")
            } catch (e: Exception) {
                Signature.getInstance("Ed25519")
            }
            else -> Signature.getInstance("SHA256withRSA")
        }
        sig.initSign(priv)
        return sig
    }

    private fun load(): KeyStore =
        KeyStore.getInstance(provider).apply { load(null) }

    private fun generate(ks: KeyStore) {
        // Note: this device's Keystore silently substitutes an EC key when
        // "Ed25519" is requested (purged in ensureKeyPair) — RSA-3072 is the
        // reliable identity; ed25519-via-Keystore stays an open question.
        generateRsa()
        android.util.Log.i(TAG, "generated RSA-3072")
    }

    private fun generateEd25519() {
        val kpg = KeyPairGenerator.getInstance("Ed25519", provider)
        kpg.initialize(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setKeySize(256)
                .build()
        )
        kpg.generateKeyPair()
    }

    private fun generateRsa() {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, provider)
        kpg.initialize(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setKeySize(3072)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setDigests(KeyProperties.DIGEST_SHA256)
                // Screenlock gate: signatures work only within 60s of a
                // successful device-credential/biometric interaction —
                // "sync takes place after a biometric auth".
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(60)
                .build()
        )
        kpg.generateKeyPair()
    }

    private fun keyTypeName(pub: PublicKey): String = when (pub.algorithm) {
        "Ed25519" -> "ssh-ed25519"
        "RSA" -> "ssh-rsa"
        else -> throw IllegalArgumentException("unsupported key algorithm ${pub.algorithm}")
    }

    private fun wireBlob(pub: PublicKey): ByteArray = when (pub.algorithm) {
        "Ed25519" -> {
            // SPKI for ed25519 ends: 0x03 0x21 0x00 <32 raw bytes>
            val raw = pub.encoded.copyOfRange(pub.encoded.size - 32, pub.encoded.size)
            sshString(keyTypeName(pub).toByteArray()) + sshString(raw)
        }
        "RSA" -> {
            val (modulus, exponent) = parseRsaSpki(pub.encoded)
            sshString(keyTypeName(pub).toByteArray()) + sshMpint(exponent) + sshMpint(modulus)
        }
        else -> throw IllegalArgumentException("unsupported key algorithm ${pub.algorithm}")
    }

    /** Minimal DER walk: SPKI -> RSAPublicKey SEQUENCE { modulus, exponent }. */
    private fun parseRsaSpki(spki: ByteArray): Pair<BigInteger, BigInteger> {
        var p = 0
        require(spki[p] == 0x30.toByte()) { "no outer SEQ" }
        p++
        val (_, afterOuter) = readLen(spki, p); p = afterOuter
        require(spki[p] == 0x30.toByte()) { "no algid SEQ" }
        p++
        val (algLen, afterAlg) = readLen(spki, p); p = afterAlg + algLen
        require(spki[p] == 0x03.toByte()) { "no BIT STRING" }
        p++
        val (_, afterBits) = readLen(spki, p); p = afterBits
        require(spki[p] == 0x00.toByte()) { "unused bits != 0" }
        p++
        require(spki[p] == 0x30.toByte()) { "no RSAPublicKey SEQ" }
        p++
        val (_, seqStart) = readLen(spki, p); p = seqStart
        val (modulus, n2) = readInt(spki, p)
        val (exponent, _) = readInt(spki, n2)
        return modulus to exponent
    }

    private fun readLen(b: ByteArray, pos: Int): Pair<Int, Int> {
        val first = b[pos].toInt() and 0xFF
        return if (first < 0x80) first to (pos + 1)
        else {
            val n = first and 0x7F
            var len = 0
            for (i in 1..n) len = (len shl 8) or (b[pos + i].toInt() and 0xFF)
            len to (pos + 1 + n)
        }
    }

    private fun readInt(b: ByteArray, pos: Int): Pair<BigInteger, Int> {
        require(b[pos] == 0x02.toByte()) { "no INTEGER" }
        val (len, content) = readLen(b, pos + 1)
        val value = BigInteger(1, b.copyOfRange(content, content + len))
        return value to (content + len)
    }

    private fun sshString(b: ByteArray): ByteArray {
        val out = ByteArray(4 + b.size)
        var i = b.size
        out[3] = (i and 0xFF).toByte(); i = i shr 8
        out[2] = (i and 0xFF).toByte(); i = i shr 8
        out[1] = (i and 0xFF).toByte(); i = i shr 8
        out[0] = (i and 0xFF).toByte()
        b.copyInto(out, 4)
        return out
    }

    private fun sshMpint(v: BigInteger): ByteArray {
        var b = v.toByteArray()
        // toByteArray() pads a leading 0x00 when the sign bit is clear;
        // SSH mpint wants the minimal two's-complement form.
        if (b.size > 1 && b[0] == 0x00.toByte()) b = b.copyOfRange(1, b.size)
        return if ((b[0].toInt() and 0x80) != 0) sshString(byteArrayOf(0x00) + b) else sshString(b)
    }

    companion object {
        private const val TAG = "S2Key"
    }
}
