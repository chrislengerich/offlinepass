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

    // -- The card simulation (no hardware) ------------------------------------
    //
    // The OpenPGP card's PSO:CDS pads the DigestInfo ON CARD (Java Card's
    // ALG_RSA_PKCS1). The tests below model exactly that: the client sends
    // the BARE DigestInfo, the "card" pads and runs the raw private-key op,
    // and the result must verify under the standard JCA/SSH verifier.

    /** The card's on-device padding: 0x00 0x01 FF…00 || DigestInfo. */
    private fun cardPad(di: ByteArray, modulusSize: Int): ByteArray {
        val pad = modulusSize - di.size - 3
        org.junit.Assert.assertTrue("DI does not fit", pad >= 8)
        return byteArrayOf(0x00, 0x01) + ByteArray(pad) { 0xFF.toByte() } +
            byteArrayOf(0x00) + di
    }

    /** The card's raw private-key op (no padding — the padding already
     *  happened): RSA/ECB/NoPadding in DECRYPT_MODE with the private key. */
    private fun cardRawRsa(block: ByteArray, privateKey: java.security.PrivateKey): ByteArray {
        val c = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding")
        c.init(javax.crypto.Cipher.DECRYPT_MODE, privateKey)
        return c.doFinal(block)
    }

    private fun keypair(bits: Int) =
        java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()

    @Test
    fun digestInfoIsTheTailOfThePaddedBlock() {
        val message = "offlinepass ssh-auth self-test".toByteArray()
        for (alg in listOf("SHA-256", "SHA-512")) {
            val block = SshRsaPkcs1.pkcs1SignBlock(alg, message, 256)
            val di = SshRsaPkcs1.digestInfo(alg, message)
            assertArrayEquals(di, block.copyOfRange(block.size - di.size, block.size))
        }
    }

    @Test
    fun cardPaddingOverDigestInfoVerifiesUnderJca() {
        val kp = keypair(2048)
        val message = "offlinepass ssh-auth self-test".toByteArray()
        for (pair in listOf("rsa-sha2-256" to "SHA256withRSA",
                "rsa-sha2-512" to "SHA512withRSA")) {
            val (sshAlg, jcaAlg) = pair
            // The client side: the bare DigestInfo goes on the wire to the card.
            val di = SshRsaPkcs1.digestInfo(sshAlg, message)
            // The card side: pad on-device, raw RSA.
            val raw = cardRawRsa(cardPad(di, 256), kp.private)
            // The verifier side: the standard JCA/SSH check.
            val v = java.security.Signature.getInstance(jcaAlg)
            v.initVerify(kp.public); v.update(message)
            org.junit.Assert.assertTrue("$sshAlg must verify", v.verify(raw))
        }
    }

    @Test
    fun corruptedDigestInfoFailsVerification() {
        val kp = keypair(2048)
        val message = "offlinepass ssh-auth self-test".toByteArray()
        val di = SshRsaPkcs1.digestInfo("rsa-sha2-512", message)
        di[di.size - 1] = (di[di.size - 1].toInt() xor 1).toByte()
        val raw = cardRawRsa(cardPad(di, 256), kp.private)
        val v = java.security.Signature.getInstance("SHA512withRSA")
        v.initVerify(kp.public); v.update(message)
        org.junit.Assert.assertFalse(v.verify(raw))
    }

    @org.junit.Test
    fun `digestWithin extracts the raw digest for the EC slot`() {
        val message = "the EC adaptation test".toByteArray()
        for (alg in listOf("SHA-256", "SHA-512", "SHA-1", "rsa-sha2-256", "rsa-sha2-512")) {
            val di = SshRsaPkcs1.digestInfo(alg, message)
            val digest = SshRsaPkcs1.digestWithin(di)
            org.junit.Assert.assertNotNull("no prefix matched for $alg", digest)
            org.junit.Assert.assertArrayEquals(
                java.security.MessageDigest.getInstance(
                    when (alg) { "rsa-sha2-256" -> "SHA-256"; "rsa-sha2-512" -> "SHA-512"; else -> alg }
                ).digest(message), digest)
        }
        // A raw hash passed straight through = NOT a DigestInfo → null
        // (the EC branch must never sign an unrecognized form).
        org.junit.Assert.assertNull(
            SshRsaPkcs1.digestWithin(byteArrayOf(1, 2, 3, 4)))
    }
}
