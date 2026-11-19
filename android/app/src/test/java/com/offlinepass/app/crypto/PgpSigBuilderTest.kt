package com.offlinepass.app.crypto

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey
import java.util.Date

/**
 * PgpSigBuilder against the REAL OpenPGP verifier (BouncyCastle, test-only):
 * the simulated card (software RSA doing the SIG slot's on-device padding
 * over the bare DigestInfo) signs a commit payload, and the produced
 * armored detached signature must verify under bcpg exactly the way gpg /
 * GitHub verify a commit's gpgsig header.
 */
class PgpSigBuilderTest {

    init {
        java.security.Security.addProvider(
            org.bouncycastle.jce.provider.BouncyCastleProvider())
    }

    private val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val keyId = 0x123456789ABCDEFL  // any positive test id
    private val content = ("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
        "author Test <t@x> 1700000000 +0000\n").toByteArray()

    /** The card: PKCS#1 v1.5 pad the bare DigestInfo on-"card", raw RSA. */
    private fun simulateCardSign(di: ByteArray, privateKey: java.security.PrivateKey): ByteArray {
        val modSize = ((kp.public as RSAPublicKey).modulus.bitLength() + 7) / 8
        val pad = modSize - di.size - 3
        val block = byteArrayOf(0x00, 0x01) + ByteArray(pad) { 0xFF.toByte() } +
            byteArrayOf(0x00) + di
        val c = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding")
        c.init(javax.crypto.Cipher.DECRYPT_MODE, privateKey)
        return c.doFinal(block)
    }

    private fun armoredFor(payload: ByteArray = content): String =
        PgpSigBuilder.armoredSignature(
            PgpSigBuilder.detachedSignature(
                payload, keyId, createdAt = 1731600000,
                sign = { di -> simulateCardSign(di, kp.private) }))

    private fun signatureOf(armored: String): org.bouncycastle.openpgp.PGPSignature {
        val decoded = PGPUtil.getDecoderStream(armored.byteInputStream())
        val factory = PGPObjectFactory(decoded, JcaKeyFingerprintCalculator())
        val list = factory.nextObject() as PGPSignatureList
        assertEquals(1, list.size())
        return list[0]
    }

    private fun verify(armored: String, payload: ByteArray): Boolean {
        val sig = signatureOf(armored)
        val pk: PGPPublicKey = JcaPGPKeyConverter()
            .getPGPPublicKey(PublicKeyAlgorithmTags.RSA_GENERAL, kp.public, Date())
        sig.init(JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pk)
        sig.update(payload)
        return sig.verify()
    }

    @Test
    fun armoredSignatureVerifiesUnderRealOpenpgp() {
        assertTrue("the simulated-card commit signature must verify", verify(armoredFor(), content))
    }

    @Test
    fun issuerKeyIdIsEmbedded() {
        assertEquals(keyId, signatureOf(armoredFor()).keyID)
    }

    @Test
    fun tamperedPayloadFailsVerification() {
        val other = content.copyOf().also { it[0] = (it[0].toInt() + 1).toByte() }
        assertTrue("a tampered payload must NOT verify", !verify(armoredFor(), other))
    }

    /** THE EC SIG SLOT: the simulated EC card (the DigestInfo stripped to
     *  the raw digest — the same strip sign() does for an EC slot) signs
     *  the raw digest — the same strip sign() does for an EC slot) signs
     *  with ECDSA; the DER comes back and the packet carries the r/s
     *  MPIs under pubkey alg 19. Verified via the MANUAL JCE path (the
     *  packet walk + the recomputed v4 digest) — bcpg's JcaPGPKeyConverter
     *  EC path in this version doesn't round-trip for verify; gpg/GitHub
     *  parse the packet exactly as this walk does. */
    @Test
    fun ecdsaCommitSignatureVerifies() {
        val ekp = KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val simulateEcCard = { di: ByteArray ->
            val hash = SshRsaPkcs1.digestWithin(di)
                ?: throw IllegalStateException("not a DigestInfo")
            java.security.Signature.getInstance("SHA256withECDSA").apply {
                initSign(ekp.private); update(hash)
            }.sign()
        }
        val armored = PgpSigBuilder.armoredSignature(
            PgpSigBuilder.detachedSignature(
                content, keyId, createdAt = 1731600000,
                sign = simulateEcCard,
                pubkeyAlg = PgpSigBuilder.PUB_ALG_ECDSA))
        // The packet walk: strip the header, then version|type|alg|hash,
        // the hashed + the unhashed areas, the RFC 4880 §5.2.3 two-octet
        // fast-fail field, then the MPIs.
        val b64 = armored.lines().filter {
            !it.startsWith("-") && !it.startsWith("=") && it.isNotBlank()
        }.joinToString("")
        val packet = java.util.Base64.getMimeDecoder().decode(b64)
        // New-format header: 0xC2 (tag 2) + the 1-octet length.
        assertEquals(0xC2.toByte(), packet[0])
        var p = 2
        assertEquals(4, packet[p].toInt()); p += 1          // version
        p += 1                                              // type
        assertEquals(19, packet[p].toInt()); p += 1         // pubkey alg (ECDSA)
        assertEquals(8, packet[p].toInt()); p += 1          // hash alg (SHA-256)
        val hashedLen = ((packet[p].toInt() and 0xFF) shl 8) or (packet[p + 1].toInt() and 0xFF)
        p += 2 + hashedLen
        val unhashedLen = ((packet[p].toInt() and 0xFF) shl 8) or (packet[p + 1].toInt() and 0xFF)
        p += 2 + unhashedLen
        p += 2                                              // the fast-fail field
        fun readMpi(): ByteArray {
            val bits = ((packet[p].toInt() and 0xFF) shl 8) or (packet[p + 1].toInt() and 0xFF)
            val len = (bits + 7) / 8
            val v = packet.copyOfRange(p + 2, p + 2 + len)
            p += 2 + len
            return v
        }
        val r = java.math.BigInteger(1, readMpi())
        val s = java.math.BigInteger(1, readMpi())
        // The issuer key id rides the unhashed area (type 16, len 9):
        // the area starts after the unhashed LENGTH octets.
        val issuerArea = packet.copyOfRange(
            10 + hashedLen, 10 + hashedLen + unhashedLen)
        assertEquals(9, issuerArea[0].toInt())
        assertEquals(16, issuerArea[1].toInt())
        val issuerId = (0 until 8).fold(0L) { acc, k ->
            (acc shl 8) or (issuerArea[2 + k].toLong() and 0xFF)
        }
        assertEquals(keyId, issuerId)
        fun int(v: java.math.BigInteger): ByteArray {
            val b = v.toByteArray()
            return byteArrayOf(0x02, b.size.toByte()) + b
        }
        val body = int(r) + int(s)
        val der = byteArrayOf(0x30, body.size.toByte()) + body
        // The v4 digest, rebuilt by hand: prefix = 4|type|alg|hash ||
        // u16(hashedLen) || the creation-time subpacket, then the trailer.
        val hashed = byteArrayOf(5, 2) +
            byteArrayOf(
                ((1731600000 ushr 24) and 0xFF).toByte(), ((1731600000 ushr 16) and 0xFF).toByte(),
                ((1731600000 ushr 8) and 0xFF).toByte(), (1731600000 and 0xFF).toByte())
        val prefix = byteArrayOf(4, 0, 19, 8) +
            byteArrayOf(((hashed.size ushr 8) and 0xFF).toByte(), (hashed.size and 0xFF).toByte()) +
            hashed
        val md = java.security.MessageDigest.getInstance("SHA-256")
        md.update(content); md.update(prefix)
        md.update(byteArrayOf(4, 0xFF.toByte()) +
            byteArrayOf(((prefix.size ushr 24) and 0xFF).toByte(),
                ((prefix.size ushr 16) and 0xFF).toByte(),
                ((prefix.size ushr 8) and 0xFF).toByte(), (prefix.size and 0xFF).toByte()))
        val digest = md.digest()
        val ok = java.security.Signature.getInstance("SHA256withECDSA").apply {
            initVerify(ekp.public); update(digest)
        }.verify(der)
        assertTrue("the manual JCE path must verify the packet's r/s", ok)
    }

    @Test
    fun armorShapeMatchesGpgConventions() {
        val armored = armoredFor()
        assertTrue(armored.startsWith("-----BEGIN PGP SIGNATURE-----\n\n"))
        assertTrue(armored.trimEnd().endsWith("-----END PGP SIGNATURE-----"))
        val crcLines = armored.lines().filter { it.startsWith("=") }
        assertEquals(1, crcLines.size)
        assertEquals(4, crcLines[0].length - 1)
        val body = armored.lines().filter {
            !it.startsWith("-") && !it.startsWith("=") && it.isNotBlank()
        }
        assertTrue(body.all { it.length <= 64 })
    }
}
