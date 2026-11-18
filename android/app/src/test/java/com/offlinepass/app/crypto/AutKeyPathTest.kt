package com.offlinepass.app.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature

/**
 * THE AUT-KEY WIRE-COMPATIBILITY PROOF (static — no card): the OpenPGP
 * card's AUT slot answers INTERNAL AUTHENTICATE with the RAW RSA result
 * over a caller-padded PKCS#1 v1.5 type-1 block (no on-card padding —
 * unlike PSO:CDS, which pads the bare DigestInfo itself). The test proves
 * that operation's output verifies as a standard ssh-rsa/rsa-sha2
 * signature — i.e. the AUT path produces wire-compatible SSH signatures,
 * so [YubiKitSshAuth.sign]'s useAut variant can serve the SSH handshake
 * once the transport handles the 512-byte command on-device.
 */
class AutKeyPathTest {

    private val alg = "rsa-sha2-512"

    /** The 2048-bit stand-in for the card's AUT key: the same operation
     *  the card performs (the raw RSA private-key op = Cipher
     *  DECRYPT_MODE = what INTERNAL AUTHENTICATE is), over the same
     *  padded block the caller constructs (SshRsaPkcs1.pkcs1SignBlock). */
    private fun autOperation(block: ByteArray, kp: java.security.KeyPair): ByteArray {
        val c = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding")
        c.init(javax.crypto.Cipher.DECRYPT_MODE, kp.private)
        return c.doFinal(block)
    }

    @Test
    fun autRawRsaOutputVerifiesAsSshSignature() {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val message = "the SSH handshake's auth payload".toByteArray(Charsets.UTF_8)

        // The caller pads the challenge: the full PKCS#1 type-1 block —
        // what INTERNAL AUTHENTICATE receives (no on-card padding).
        val modulusSize = (kp.public as java.security.interfaces.RSAPublicKey).modulus.bitLength() / 8
        val block = SshRsaPkcs1.pkcs1SignBlock(alg, message, modulusSize)
        assertEquals("the challenge = the modulus length", modulusSize, block.size)
        assertEquals("type-1 header", 0x00, block[0].toInt())
        assertEquals("type-1 header", 0x01, block[1].toInt())

        // The card's answer = the raw RSA over that block.
        val raw = autOperation(block, kp)
        assertEquals("the raw RSA = the modulus length", modulusSize, raw.size)

        // THE PROOF: the raw output = a standard RSASSA-PKCS1-v1_5
        // signature over the message — what the SSH handshake's
        // public-key verify does.
        assertTrue(
            "the AUT's raw-RSA output must verify as an ssh-rsa signature",
            Signature.getInstance("SHA512withRSA").apply {
                initVerify(kp.public)
                update(message)
            }.verify(raw))
    }

    @Test
    fun autSignatureEqualsStandardSignOfSameBlock() {
        // Equivalence: the raw-RSA-over-padded-block result = byte-identical
        // to what a standard RSASSA-PKCS1-v1_5 sign produces — the SSH side
        // cannot tell the AUT path from a software signer.
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val message = "equivalence".toByteArray(Charsets.UTF_8)
        val block = SshRsaPkcs1.pkcs1SignBlock(alg, message, 256)

        val viaAut = autOperation(block, kp)
        val viaStandard = Signature.getInstance("SHA512withRSA").apply {
            initSign(kp.private)
            update(message)
        }.sign()

        assertTrue("the AUT path must be byte-identical to the standard sign",
            viaAut.contentEquals(viaStandard))
    }

    @Test
    fun tamperedChallengeProducesUnverifiableSignature() {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val message = "tamper".toByteArray(Charsets.UTF_8)
        val block = SshRsaPkcs1.pkcs1SignBlock(alg, message, 256).copyOf()
        block[block.size - 1] = (block[block.size - 1].toInt() xor 1).toByte()
        val raw = autOperation(block, kp)
        assertTrue(
            "a tampered challenge must NOT verify",
            !Signature.getInstance("SHA512withRSA").apply {
                initVerify(kp.public)
                update(message)
            }.verify(raw))
    }
}
