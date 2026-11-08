package com.linuxpass.app.vault

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

/**
 * Device-wrap: encrypts a QRFT paste payload to a paired Chrome extension
 * (Plan 2, docs/extension-protocol.md).
 *
 * Standard primitives only (per plan: no hand-rolled crypto):
 *   ephemeral ECDH P-256 → shared X   (KeyAgreement "ECDH")
 *   HKDF-SHA256                     (RFC 5869 over HmacSHA256 — JCE ships
 *                                    no HKDF; this is the standard extract/
 *                                    expand construction, cross-checked
 *                                    against WebCrypto by fixed vectors)
 *   AES-256-GCM, AAD-bound header   (Cipher "AES/GCM/NoPadding")
 *
 * Wire format (the QRFT payload string the generator page transmits):
 * {"v":1,"type":"linuxpass-wrap",
 *  "wrap":{"keyId":"<hex8 of SHA-256(device pub)>","epk":"<b64 raw point>"},
 *  "iv":"<b64>","ct":"<b64>"}
 */
object DeviceWrap {

    const val TYPE = "linuxpass-wrap"
    private const val VERSION = 1
    private val PASTE_INFO = "linuxpass-paste-wrap-v1".toByteArray(Charsets.UTF_8)

    /** Wraps [payloadJson] to the device described by [device]. */
    fun wrap(payloadJson: String, device: DeviceRecord): String {
        val gen = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        val eph = gen.generateKeyPair()
        val ephPubRaw = rawPoint((eph.public as ECPublicKey).w)
        return core(payloadJson, rawPointB64(device.pub), device.keyId, eph.private, ephPubRaw,
            ByteArray(12).also { SecureRandom().nextBytes(it) })
    }

    /** Deterministic core (test-visible): fixed ephemeral key + IV. */
    internal fun wrapDeterministic(
        payloadJson: String,
        devicePubRaw: ByteArray,
        keyIdHex: String,
        ephPrivScalar: ByteArray,
        ephPubRaw: ByteArray,
        iv: ByteArray
    ): String {
        val params = p256Params()
        val priv = KeyFactory.getInstance("EC").generatePrivate(
            ECPrivateKeySpec(BigInteger(1, ephPrivScalar), params))
        return core(payloadJson, devicePubRaw, keyIdHex, priv, ephPubRaw, iv)
    }

    private fun core(
        payloadJson: String,
        devicePubRaw: ByteArray,
        keyIdHex: String,
        ephPriv: java.security.PrivateKey,
        ephPubRaw: ByteArray,
        iv: ByteArray
    ): String {
        val devicePub = importPublicKey(devicePubRaw)
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(ephPriv)
        agreement.doPhase(devicePub, true)
        val sharedX = agreement.generateSecret() // X coordinate, zero-padded

        val wrapKek = Hkdf.derive(sharedX, keyIdHex.hexToBytes(), PASTE_INFO, 32)
        val aad = "$PASTE_AAD_PREFIX$keyIdHex:${Base64.getEncoder().encodeToString(ephPubRaw)}"
            .toByteArray(Charsets.UTF_8)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(wrapKek, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad)
        val ct = cipher.doFinal(payloadJson.toByteArray(Charsets.UTF_8))

        val b64 = Base64.getEncoder()
        return JSONObject()
            .put("v", VERSION)
            .put("type", TYPE)
            .put("wrap", JSONObject()
                .put("keyId", keyIdHex)
                .put("epk", b64.encodeToString(ephPubRaw)))
            .put("iv", b64.encodeToString(iv))
            .put("ct", b64.encodeToString(ct))
            .toString()
    }

    // -- key parsing ----------------------------------------------------------

    private const val PASTE_AAD_PREFIX = "linuxpass-paste-wrap-v1:"

    private fun p256Params(): ECParameterSpec =
        AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)

    /** 65-byte uncompressed point (0x04 || X || Y) → JCE public key. */
    private fun importPublicKey(raw: ByteArray): java.security.PublicKey {
        require(raw.size == 65 && raw[0] == 0x04.toByte()) { "Not an uncompressed P-256 point" }
        val half = 32
        val x = BigInteger(1, raw.copyOfRange(1, 1 + half))
        val y = BigInteger(1, raw.copyOfRange(1 + half, 1 + 2 * half))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), p256Params()))
    }

    private fun rawPoint(w: ECPoint): ByteArray {
        val pad = { v: BigInteger ->
            val b = v.toByteArray() // may carry a sign byte / shorter length
            val out = ByteArray(32)
            System.arraycopy(b, if (b.size > 32) b.size - 32 else 0, out,
                if (b.size > 32) 0 else 32 - b.size, if (b.size > 32) 32 else b.size)
            out
        }
        return byteArrayOf(0x04) + pad(w.affineX) + pad(w.affineY)
    }

    private fun rawPointB64(b64: String): ByteArray =
        Base64.getDecoder().decode(b64)

    private fun String.hexToBytes(): ByteArray {
        require(length % 2 == 0) { "Bad hex" }
        return ByteArray(length / 2) { i ->
            substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}

/** RFC 5869 HKDF-SHA256 (extract + expand). Test vectors pin the parameters
 *  against the extension's WebCrypto HKDF — see DeviceWrapTest. */
internal object Hkdf {
    fun derive(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // extract
        mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        // expand
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val okm = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            val n = minOf(t.size, length - pos)
            System.arraycopy(t, 0, okm, pos, n)
            pos += n
            counter++
        }
        return okm
    }
}
