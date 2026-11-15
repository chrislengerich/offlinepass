package com.offlinepass.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * YubiKeySshIdentity's YubiKit branch, without hardware: the "card" is a
 * software RSA key doing exactly what the OpenPGP applet does with the
 * bare DigestInfo it receives (on-device PKCS#1 v1.5 padding + raw RSA —
 * see SshRsaPkcs1Test for the padding model). The injected signer lambda
 * stands in for YubiKitSshAuth, so the SSH wire framing, the payload the
 * signer gets, and the PIN-cancelled path are all testable.
 */
class YubiKeySshIdentityTest {

    private fun sshString(b: ByteArray): ByteArray {
        val out = ByteArray(4 + b.size)
        out[0] = ((b.size ushr 24) and 0xFF).toByte()
        out[1] = ((b.size ushr 16) and 0xFF).toByte()
        out[2] = ((b.size ushr 8) and 0xFF).toByte()
        out[3] = (b.size and 0xFF).toByte()
        b.copyInto(out, 4)
        return out
    }

    private fun readString(b: ByteArray, off: Int): Pair<ByteArray, Int> {
        val len = ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)
        return b.copyOfRange(off + 4, off + 4 + len) to off + 4 + len
    }

    /** The card: pad the received DigestInfo on-device, raw RSA. */
    private fun simulateCardSign(di: ByteArray, privateKey: java.security.PrivateKey, modulusSize: Int): ByteArray {
        val pad = modulusSize - di.size - 3
        assertTrue("DI does not fit", pad >= 8)
        val block = byteArrayOf(0x00, 0x01) + ByteArray(pad) { 0xFF.toByte() } +
            byteArrayOf(0x00) + di
        val c = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding")
        c.init(javax.crypto.Cipher.DECRYPT_MODE, privateKey)
        return c.doFinal(block)
    }

    @Test
    fun yubiKitSignProducesSshFramingThatVerifies() {
        val kp = java.security.KeyPairGenerator.getInstance("RSA")
            .apply { initialize(2048) }.generateKeyPair()
        val pub = kp.public as java.security.interfaces.RSAPublicKey
        val e = pub.publicExponent.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        val n = pub.modulus.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        val blob = sshString("ssh-rsa".toByteArray()) + sshString(e) + sshString(n)
        val line = "ssh-rsa " + java.util.Base64.getEncoder().encodeToString(blob)
        val modulusSize = (pub.modulus.bitLength() + 7) / 8

        var receivedPayload: ByteArray? = null
        val identity = YubiKeySshIdentity(
            client = null,
            authSubkeyId = 0x63EBEE3E00698013L,
            publicKeyLine = line,
            interaction = { null },
            yubiKitSigner = { payload ->
                receivedPayload = payload
                simulateCardSign(payload, kp.private, modulusSize)
            })

        val message = "offlinepass ssh-auth self-test".toByteArray()
        val wire = identity.getSignature(message, "rsa-sha2-512")
        assertNotNull("the YubiKit branch must produce a signature", wire)

        // The signer received the BARE DigestInfo (83 bytes for SHA-512:
        // 19-byte prefix + 64-byte digest), not a padded block.
        val di = receivedPayload!!
        assertEquals(83, di.size)
        assertEquals(0x30.toByte(), di[0])

        // The wire: string(algorithm) + string(raw signature).
        val (alg, p1) = readString(wire!!, 0)
        val (raw, _) = readString(wire, p1)
        assertArrayEquals("rsa-sha2-512".toByteArray(), alg)
        assertEquals(modulusSize, raw.size)

        // The full loop: the wire signature verifies under the standard
        // JCA/SSH verifier for the enrolled line's key.
        val v = java.security.Signature.getInstance("SHA512withRSA")
        v.initVerify(kp.public); v.update(message)
        assertTrue(v.verify(raw))
    }

    @Test
    fun signerReturningNullMeansPinCancelled() {
        val kp = java.security.KeyPairGenerator.getInstance("RSA")
            .apply { initialize(2048) }.generateKeyPair()
        val pub = kp.public as java.security.interfaces.RSAPublicKey
        val e = pub.publicExponent.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        val n = pub.modulus.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        val blob = sshString("ssh-rsa".toByteArray()) + sshString(e) + sshString(n)
        val line = "ssh-rsa " + java.util.Base64.getEncoder().encodeToString(blob)

        val identity = YubiKeySshIdentity(
            client = null, authSubkeyId = 1L, publicKeyLine = line,
            interaction = { null }, yubiKitSigner = { null })

        assertNull(identity.getSignature("x".toByteArray(), "rsa-sha2-512"))
        assertEquals("OpenPGP PIN cancelled", YubiKeySshIdentity.lastAuthError)
    }
}
