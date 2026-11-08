package com.offlinepass.app.vault

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
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
import org.json.JSONArray
import org.json.JSONObject

/**
 * Device-wrap: encrypts a QRFT paste payload to paired Chrome extensions
 * (Plan 2 rev 2, docs/extension-protocol.md).
 *
 * Wrap-once, target-many: the payload is encrypted once under a random CEK;
 * every selected paired key gets its own wrapped-CEK blob. Any one of the
 * selected keys can open the paste.
 *
 * Standard primitives only (per plan: no hand-rolled crypto):
 *   ephemeral ECDH P-256 → shared X   (KeyAgreement "ECDH")
 *   HKDF-SHA256                     (RFC 5869 over HmacSHA256 — JCE ships
 *                                    no HKDF; this is the standard extract/
 *                                    expand construction, cross-checked
 *                                    against WebCrypto by fixed vectors)
 *   AES-256-GCM, AAD-bound layers   (Cipher "AES/GCM/NoPadding")
 *
 * Wire format (the QRFT payload string the generator page transmits):
 * {"v":1,"type":"linuxpass-wrap",
 *  "payload":{"iv":"<b64>","ct":"<b64>"},
 *  "targets":[{"keyId":"<hex8 of SHA-256(credId)>","epk":"<b64 raw point>",
 *              "iv":"<b64>","ct":"<b64>"}]}
 */
object DeviceWrap {

    const val TYPE = "linuxpass-wrap"
    private const val VERSION = 1
    private val PASTE_INFO = "linuxpass-paste-wrap-v1".toByteArray(Charsets.UTF_8)
    private const val AAD_PREFIX = "linuxpass-paste-wrap-v1:"

    /** Wraps [payloadJson] to every device in [devices] (≥1 required). */
    fun wrap(payloadJson: String, devices: List<DeviceRecord>): String {
        require(devices.isNotEmpty()) { "No paste targets selected" }
        val random = SecureRandom()
        val cek = ByteArray(32).also(random::nextBytes)
        val payloadIv = ByteArray(12).also(random::nextBytes)
        val payloadCt = aesGcmEncrypt(cek, payloadIv, PASTE_INFO, payloadJson.toByteArray(Charsets.UTF_8))

        val gen = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        val targets = JSONArray()
        for (device in devices) {
            val eph = gen.generateKeyPair()
            val ephPubRaw = rawPoint((eph.public as ECPublicKey).w)
            val kek = targetKek(device.pub.decodeB64(), device.keyId, eph.private, ephPubRaw)
            val iv = ByteArray(12).also(random::nextBytes)
            val aad = "$AAD_PREFIX${device.keyId}:${ephPubRaw.encodeB64()}"
            val ct = aesGcmEncrypt(kek, iv, aad.toByteArray(Charsets.UTF_8), cek)
            targets.put(JSONObject()
                .put("keyId", device.keyId)
                .put("epk", ephPubRaw.encodeB64())
                .put("iv", iv.encodeB64())
                .put("ct", ct.encodeB64()))
        }
        return JSONObject()
            .put("v", VERSION)
            .put("type", TYPE)
            .put("payload", JSONObject()
                .put("iv", payloadIv.encodeB64())
                .put("ct", payloadCt.encodeB64()))
            .put("targets", targets)
            .toString()
    }

    /** Deterministic core (test-visible): pinned CEK + per-target keys/IVs. */
    internal data class TestTarget(
        val devicePubRaw: ByteArray,
        val keyIdHex: String,
        val ephScalar: ByteArray,
        val ephPubRaw: ByteArray,
        val iv: ByteArray
    )

    internal fun wrapDeterministic(payloadJson: String, cek: ByteArray, targets: List<TestTarget>): String {
        val payloadIv = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c)
        val payloadCt = aesGcmEncrypt(cek, payloadIv, PASTE_INFO, payloadJson.toByteArray(Charsets.UTF_8))
        val params = p256Params()
        val factory = KeyFactory.getInstance("EC")
        val arr = JSONArray()
        for (t in targets) {
            val ephPriv: PrivateKey = factory.generatePrivate(
                ECPrivateKeySpec(BigInteger(1, t.ephScalar), params))
            val kek = targetKek(t.devicePubRaw, t.keyIdHex, ephPriv, t.ephPubRaw)
            val aad = "$AAD_PREFIX${t.keyIdHex}:${t.ephPubRaw.encodeB64()}"
            val ct = aesGcmEncrypt(kek, t.iv, aad.toByteArray(Charsets.UTF_8), cek)
            arr.put(JSONObject()
                .put("keyId", t.keyIdHex)
                .put("epk", t.ephPubRaw.encodeB64())
                .put("iv", t.iv.encodeB64())
                .put("ct", ct.encodeB64()))
        }
        return JSONObject()
            .put("v", VERSION)
            .put("type", TYPE)
            .put("payload", JSONObject()
                .put("iv", payloadIv.encodeB64())
                .put("ct", payloadCt.encodeB64()))
            .put("targets", arr)
            .toString()
    }

    // -- crypto helpers -------------------------------------------------------

    /** ECDH(ephPriv, devicePub) → HKDF-SHA256(shared, salt = keyId, info). */
    private fun targetKek(devicePubRaw: ByteArray, keyIdHex: String, ephPriv: PrivateKey, ephPubRaw: ByteArray): ByteArray {
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(ephPriv)
        agreement.doPhase(importPublicKey(devicePubRaw), true)
        val sharedX = agreement.generateSecret() // X coordinate, zero-padded
        return Hkdf.derive(sharedX, keyIdHex.hexToBytes(), PASTE_INFO, 32)
    }

    private fun aesGcmEncrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    // -- key parsing ----------------------------------------------------------

    private fun p256Params(): ECParameterSpec =
        AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)

    /** 65-byte uncompressed point (0x04 || X || Y) → JCE public key. */
    private fun importPublicKey(raw: ByteArray): PublicKey {
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

    private fun String.hexToBytes(): ByteArray {
        require(length % 2 == 0) { "Bad hex" }
        return ByteArray(length / 2) { i ->
            substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun ByteArray.encodeB64(): String = Base64.getEncoder().encodeToString(this)
    private fun String.decodeB64(): ByteArray = Base64.getDecoder().decode(this)
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
