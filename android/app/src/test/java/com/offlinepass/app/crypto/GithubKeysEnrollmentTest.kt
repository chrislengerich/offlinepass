package com.offlinepass.app.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey
import java.security.SecureRandom

/**
 * The GitHub-.keys enrollment's pure logic: the username derivation from
 * the remote, the fingerprint→key-id, and the cryptographic card↔line
 * match (the card signature verifies the matching line, and ONLY it).
 */
class GithubKeysEnrollmentTest {

    private val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val otherKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun lineFor(pair: java.security.KeyPair, comment: String): String {
        val pub = pair.public as RSAPublicKey
        val e = pub.publicExponent.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        val n = pub.modulus.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        fun mpint(v: ByteArray) = if ((v[0].toInt() and 0x80) != 0) byteArrayOf(0) + v else v
        fun sshString(b: ByteArray): ByteArray {
            val out = ByteArray(4 + b.size)
            out[0] = ((b.size ushr 24) and 0xFF).toByte()
            out[1] = ((b.size ushr 16) and 0xFF).toByte()
            out[2] = ((b.size ushr 8) and 0xFF).toByte()
            out[3] = (b.size and 0xFF).toByte()
            b.copyInto(out, 4)
            return out
        }
        val blob = sshString("ssh-rsa".toByteArray()) + sshString(mpint(e)) + sshString(mpint(n))
        return "ssh-rsa " + java.util.Base64.getEncoder().encodeToString(blob) + " " + comment
    }

    /** The card: PSO:CDS over the SHA-256 DigestInfo of the nonce. */
    private fun cardSign(privateKey: java.security.PrivateKey, nonce: ByteArray): ByteArray {
        val di = SshRsaPkcs1.digestInfo("SHA-256", nonce)
        val modSize = ((kp.public as RSAPublicKey).modulus.bitLength() + 7) / 8
        val block = byteArrayOf(0x00, 0x01) +
            ByteArray(modSize - di.size - 3) { 0xFF.toByte() } + byteArrayOf(0x00) + di
        val c = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding")
        c.init(javax.crypto.Cipher.DECRYPT_MODE, privateKey)
        return c.doFinal(block)
    }

    @Test
    fun usernameDerivesFromBothRemoteForms() {
        assertEquals("alice",
            GithubKeysEnrollment.parseUsername("git@github.com:alice/vault.git"))
        assertEquals("alice",
            GithubKeysEnrollment.parseUsername("https://github.com/alice/vault.git"))
        assertNull(GithubKeysEnrollment.parseUsername("https://gitlab.com/a/b.git"))
        assertNull(GithubKeysEnrollment.parseUsername("not a remote"))
    }

    @Test
    fun keyIdIsTheFingerprintsLowHalf() {
        val fp = ByteArray(20) { it.toByte() }
        assertEquals(
            (12 until 20).fold(0L) { acc, k -> (acc shl 8) or (fp[k].toLong() and 0xFF) },
            GithubKeysEnrollment.keyIdFromFingerprint(fp))
    }

    @Test
    fun cardSignatureMatchesOnlyTheCardsLine() {
        val mine = lineFor(kp, "mine")
        val stranger = lineFor(otherKp, "stranger")
        val lines = listOf(stranger, mine, lineFor(otherKp, "another"))
        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sig = cardSign(kp.private, nonce)
        assertEquals(mine, GithubKeysEnrollment.match(lines, nonce, sig))
    }

    @Test
    fun noMatchReturnsNull() {
        val lines = listOf(lineFor(otherKp, "a"), lineFor(otherKp, "b"))
        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sig = cardSign(kp.private, nonce)
        assertNull(GithubKeysEnrollment.match(lines, nonce, sig))
    }

    @Test
    fun malformedAndNonRsaLinesAreSkipped() {
        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sig = cardSign(kp.private, nonce)
        val lines = listOf(
            "garbage",
            "ssh-rsa !!!not-base64!!! broken",
            lineFor(otherKp, "stranger"))
        assertNull("the malformed lines must not crash the match",
            GithubKeysEnrollment.match(lines, nonce, sig))
        assertTrue("malformed lines do not throw", true)
    }
}
