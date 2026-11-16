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
