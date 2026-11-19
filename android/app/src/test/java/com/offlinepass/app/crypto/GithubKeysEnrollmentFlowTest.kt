package com.offlinepass.app.crypto

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey

/**
 * The FULL enrollment orchestration with injected dependencies — the same
 * flow the UI drives, stubbed end to end: the .keys FETCH is a canned
 * body, the card is the software SIG-slot model, and the enrollment
 * callback captures what would be persisted.
 */
class GithubKeysEnrollmentFlowTest {

    private val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val otherKp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun sshLine(pair: KeyPair, comment: String): String {
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

    private fun cardSign(nonce: ByteArray): ByteArray {
        val di = SshRsaPkcs1.digestInfo("SHA-256", nonce)
        val modSize = ((kp.public as RSAPublicKey).modulus.bitLength() + 7) / 8
        val block = byteArrayOf(0x00, 0x01) +
            ByteArray(modSize - di.size - 3) { 0xFF.toByte() } + byteArrayOf(0x00) + di
        val c = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding")
        c.init(javax.crypto.Cipher.DECRYPT_MODE, kp.private)
        return c.doFinal(block)
    }

    private fun keysBody(vararg lines: String) = lines.joinToString("\n")

    @Test
    fun happyPathFetchesMatchesAndEnrolls() = runBlocking {
        val mine = sshLine(kp, "mine")
        val fetched = mutableListOf<String>()
        val enrolled = mutableListOf<Triple<String, Long, String>>()
        val status = GithubKeysEnrollment.enroll(
            remote = "git@github.com:alice/vault.git",
            fetchLines = { user ->
                fetched += user
                GithubKeysEnrollment.filterKeyLines(
                    keysBody("garbage", mine, "ecdsa-sha2-nistp256 AAAAother e"))
            },
            cardIdentity = { _ -> 0x123456789ABCDEFL to ByteArray(20) },
            cardSign = { _, nonce -> cardSign(nonce) },
            enroll = { line, id, slot -> enrolled += Triple(line, id, slot) })
        assertEquals(listOf("alice"), fetched)
        assertEquals(1, enrolled.size)
        assertEquals(mine, enrolled[0].first)
        assertEquals(0x123456789ABCDEFL, enrolled[0].second)
        // The stub proves BOTH slots — the AUT (the dedicated auth key)
        // wins the discovery order.
        assertEquals("AUTH", enrolled[0].third)
        assertTrue(status.contains("Enrolled the AUTH-slot key"))
    }

    @Test
    fun zeroMatchNamesTheFix() = runBlocking {
        val stranger = sshLine(otherKp, "stranger")
        val status = GithubKeysEnrollment.enroll(
            remote = "git@github.com:alice/vault.git",
            fetchLines = { GithubKeysEnrollment.filterKeyLines(keysBody(stranger)) },
            cardIdentity = { _ -> 0x1L to ByteArray(20) },
            cardSign = { _, nonce -> cardSign(nonce) },
            enroll = { _, _, _ -> throw AssertionError("must not enroll") })
        assertTrue(status.contains("No GitHub key of alice matches this security key"))
        assertTrue(status.contains("github.com/settings/keys"))
    }

    @Test
    fun autTransportFailureFallsThroughToSig() = runBlocking {
        // The RSA-4096 dead end, simulated: the AUTH slot's identity reads
        // fine but the proof throws (the 0x6581) — the discovery falls
        // through to the SIGNATURE slot and enrolls ITS key with the slot
        // recorded. The transport then follows the enrolled key.
        val mine = sshLine(kp, "mine-sig")
        val enrolled = mutableListOf<Triple<String, Long, String>>()
        val status = GithubKeysEnrollment.enroll(
            remote = "git@github.com:alice/vault.git",
            fetchLines = { GithubKeysEnrollment.filterKeyLines(keysBody(mine)) },
            cardIdentity = { useAut ->
                if (useAut) 0x2L to ByteArray(20) else 0x123456789ABCDEFL to ByteArray(20)
            },
            cardSign = { useAut, nonce ->
                if (useAut) throw java.io.IOException(
                    "the AUTH slot answered 0x6581 (command too long)")
                cardSign(nonce)
            },
            enroll = { line, id, slot -> enrolled += Triple(line, id, slot) })
        assertEquals(1, enrolled.size)
        assertEquals("SIGNATURE", enrolled[0].third)
        assertEquals(mine, enrolled[0].first)
        assertTrue(status.contains("Enrolled the SIGNATURE-slot key"))
    }

    @Test
    fun bothSlotsUnprovableNamesTheCard() = runBlocking {
        val status = GithubKeysEnrollment.enroll(
            remote = "git@github.com:alice/vault.git",
            fetchLines = { GithubKeysEnrollment.filterKeyLines(keysBody(sshLine(kp, "mine"))) },
            cardIdentity = { _ -> throw java.io.IOException("no YubiKey connected") },
            cardSign = { _, _ -> throw AssertionError("must not be reached") },
            enroll = { _, _, _ -> throw AssertionError("must not enroll") })
        assertTrue(status.contains("The card could not prove a key"))
        assertTrue(status.contains("no YubiKey connected"))
    }

    @Test
    fun unparseableRemoteStopsEarly() = runBlocking {
        var fetched = false
        val status = GithubKeysEnrollment.enroll(
            remote = "not a remote",
            fetchLines = { fetched = true; emptyList() },
            cardIdentity = { _ -> 1L to ByteArray(20) },
            cardSign = { _, _ -> byteArrayOf() },
            enroll = { _, _, _ -> throw AssertionError("must not enroll") })
        assertTrue(status.contains("does not name a GitHub user"))
        assertEquals(false, fetched)
    }

    @Test
    fun emptyKeysAndFetchFailuresSurface() = runBlocking {
        val s1 = GithubKeysEnrollment.enroll(
            remote = "git@github.com:alice/v.git",
            fetchLines = { emptyList<String>() },
            cardIdentity = { _ -> 1L to ByteArray(20) },
            cardSign = { _, _ -> byteArrayOf() },
            enroll = { _, _, _ -> throw AssertionError() })
        assertTrue(s1.contains("No SSH keys registered on GitHub for alice"))

        val s2 = GithubKeysEnrollment.enroll(
            remote = "git@github.com:alice/v.git",
            fetchLines = { throw java.io.IOException("HTTP 404") },
            cardIdentity = { _ -> 1L to ByteArray(20) },
            cardSign = { _, _ -> byteArrayOf() },
            enroll = { _, _, _ -> throw AssertionError() })
        assertTrue(s2.contains("HTTP 404"))
    }

    @Test
    fun cardIdentityFailureSurfaces() = runBlocking {
        val status = GithubKeysEnrollment.enroll(
            remote = "git@github.com:alice/v.git",
            fetchLines = { GithubKeysEnrollment.filterKeyLines(keysBody(sshLine(kp, "mine"))) },
            cardIdentity = { throw java.io.IOException("no YubiKey connected") },
            cardSign = { _, _ -> byteArrayOf() },
            enroll = { _, _, _ -> throw AssertionError("must not enroll") })
        assertTrue(status.contains("The card could not prove a key"))
        assertTrue(status.contains("no YubiKey connected"))
    }

    @Test
    fun filterKeepsOnlyKeyLines() {
        val body = """
            junk line
            ssh-rsa AAAAone comment
            ecdsa-sha2-nistp256 AAAAtwo
            sk-ssh-ed25519@openssh.com AAAAthree
            ssh-rsa
        """.trimIndent()
        val lines = GithubKeysEnrollment.filterKeyLines(body)
        assertEquals(3, lines.size)
        assertTrue(lines[0].startsWith("ssh-rsa AAAAone"))
    }
}
