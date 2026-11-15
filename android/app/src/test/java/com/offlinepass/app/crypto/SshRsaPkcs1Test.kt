package com.offlinepass.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** SshRsaPkcs1: the DigestInfo framing + the PKCS#1 v1.5 padding that the
 *  card's PSO:CDS expects, plus the full sign→pad→verify loop through the
 *  ssh-rsa line's public key. */
class SshRsaPkcs1Test {

    @Test
    fun digestInfoMatchesRfc8017Form() {
        val block = SshRsaPkcs1.pkcs1SignBlock("SHA-256", ByteArray(0), 128)
        assertEquals(128, block.size)
        assertEquals(0x00.toByte(), block[0])
        assertEquals(0x01.toByte(), block[1])
        assertEquals(0xFF.toByte(), block[2])
        // the DI starts after the 00 terminator: 3 + 74 pad = 77
        assertEquals(0x00.toByte(), block[76])
        val di = block.copyOfRange(77, 128)
        assertEquals(51, di.size)
        val expected = byteArrayOf(
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01,
            0x65.toByte(), 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20.toByte())
        assertArrayEquals(expected, di.copyOfRange(0, expected.size))
        // the SHA-256 of "" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assertEquals(0xe3.toByte(), di[19])
        assertEquals(0xb0.toByte(), di[20])
    }

    @Test
    fun sha512BlockPadsToModulusSize() {
        val block = SshRsaPkcs1.pkcs1SignBlock("SHA-512", byteArrayOf(1, 2, 3), 512)
        assertEquals(512, block.size)
        assertEquals(0x01.toByte(), block[1])
        // the SHA-512 DI = 19 + 64 = 83 bytes; its 0x40 = at index 18
        assertEquals(0x40.toByte(), block[512 - 83 + 18])
    }

    @Test
    fun digestInfoMatchesJcaInternalBlock() {
        val kp = java.security.KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()
        val message = "offlinepass ssh-auth self-test".toByteArray()
        val myBlock = SshRsaPkcs1.pkcs1SignBlock("SHA-512", message, 256)
        // The JCA's SHA512withRSA signature: its internal padded DigestInfo
        // is RECOVERABLE via the public-key decrypt (the padding checked).
        val sig = java.security.Signature.getInstance("SHA512withRSA")
        sig.initSign(kp.private); sig.update(message)
        val jcaSig = sig.sign()
        val dec = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding")
        dec.init(javax.crypto.Cipher.DECRYPT_MODE, kp.public)
        val digestInfo = dec.doFinal(jcaSig)
        // My block's DigestInfo (after the 00 01 FF…00) = the JCA's — the
        // card RSA-signing my block produces a signature the JCA verifies.
        // The 256-byte block: pad = 256 - 83 - 3 = 170, so the DI starts
        // at index 173.
        assertArrayEquals(myBlock.copyOfRange(173, 256), digestInfo)
    }

    @Test
    fun rawRsaOfMyBlockVerifiesAsTheSignature() {
        val kp = java.security.KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()
        val rsaPriv = kp.private as java.security.interfaces.RSAPrivateKey
        val rsaPub = kp.public as java.security.interfaces.RSAPublicKey
        val message = "offlinepass ssh-auth self-test".toByteArray()
        val myBlock = SshRsaPkcs1.pkcs1SignBlock("SHA-512", message, 256)
        // The card's raw RSA over the block (the value as an integer):
        val sigRaw = java.math.BigInteger(1, myBlock)
            .modPow(rsaPriv.privateExponent, rsaPub.modulus).toByteArray()
            .let { if (it.size > 256) it.copyOfRange(it.size - 256, it.size) else it }
        val padded = ByteArray(256 - sigRaw.size) + sigRaw
        // The JCA verifies it as a SHA512withRSA signature over the message:
        val verifier = java.security.Signature.getInstance("SHA512withRSA")
        verifier.initVerify(kp.public); verifier.update(message)
        assertTrue(verifier.verify(padded))
    }
}
