package com.offlinepass.app.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * PgpSshBridge tests: hand-built OpenPGP v4 signature packets over a known
 * payload-agnostic body (the bridge only parses the packet envelope + MPIs)
 * must map to the correct SSH wire signatures; the key-material → OpenSSH
 * line conversion round-trips.
 */
class PgpSshBridgeTest {

    // -- OpenPGP packet builders ---------------------------------------------

    private fun mpi(value: ByteArray): ByteArray {
        var v = value
        while (v.size > 1 && v[0] == 0x00.toByte()) v = v.copyOfRange(1, v.size)
        val bits = java.math.BigInteger(1, v).bitLength()
        val len = (bits + 7) / 8
        val content = v.copyOfRange(v.size - len, v.size)
        val out = ByteArray(2 + len)
        out[0] = ((bits ushr 8) and 0xFF).toByte()
        out[1] = (bits and 0xFF).toByte()
        content.copyInto(out, 2)
        return out
    }

    private fun u16(v: Int) = byteArrayOf(((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    /** A v4 signature packet body: version, type, pubkeyAlg, hashAlg, empty
     *  hashed/unhashed subpackets, then the given MPIs. */
    private fun sigBody(pubkeyAlg: Int, hashAlg: Int, vararg mpis: ByteArray): ByteArray {
        val mpiBytes = mpis.flatMap { m -> mpi(m).toList() }.toByteArray()
        return byteArrayOf(4, 0, pubkeyAlg.toByte(), hashAlg.toByte()) +
            u16(0) + u16(0) + mpiBytes
    }

    /** Wraps a body into a new-format signature packet (tag 2), with the
     *  proper new-format length encoding (same as real signers emit). */
    private fun packet(body: ByteArray): ByteArray {
        val lenEnc = when {
            body.size < 192 -> byteArrayOf(body.size.toByte())
            body.size <= 8383 -> {
                val n = body.size - 192
                byteArrayOf(((n ushr 8) + 192).toByte(), (n and 0xFF).toByte())
            }
            else -> byteArrayOf(255.toByte()) + u16(body.size ushr 16) + u16(body.size and 0xFFFF)
        }
        return byteArrayOf(0xC2.toByte()) + lenEnc + body
    }

    private fun armor(packet: ByteArray): String {
        val b64 = java.util.Base64.getEncoder().encodeToString(packet)
        return "-----BEGIN PGP SIGNATURE-----\n$b64\n-----END PGP SIGNATURE-----\n"
    }

    private fun sshString(b: ByteArray): ByteArray {
        val out = ByteArray(4 + b.size)
        out[0] = ((b.size ushr 24) and 0xFF).toByte()
        out[1] = ((b.size ushr 16) and 0xFF).toByte()
        out[2] = ((b.size ushr 8) and 0xFF).toByte()
        out[3] = (b.size and 0xFF).toByte()
        b.copyInto(out, 4)
        return out
    }

    // -- tests: OpenPGP signature → SSH signature -----------------------------

    @Test
    fun rsaSignatureMapsToRsaSha2_256WithPadding() {
        val modulusSize = 64 // 512-bit test modulus → sig must pad to 64 bytes
        val raw = byteArrayOf(1, 2, 3, 4) // short MPI (leading zeros stripped)
        val line = PgpSshBridge.parsePublicKeyLine(
            "ssh-rsa " + java.util.Base64.getEncoder().encodeToString(
                sshString("ssh-rsa".toByteArray()) + sshString(byteArrayOf(1, 0, 1)) +
                    sshString(ByteArray(modulusSize)) // n = 64 zero bytes (test size)
            ) + " test-comment"
        )
        assertEquals(modulusSize, PgpSshBridge.rsaModulusSize(line.wireBlob))

        val out = PgpSshBridge.openPgpToSshSignature(
            armor(packet(sigBody(1, 8, raw))), line)

        // string("rsa-sha2-256") + string(64-byte padded sig)
        val expected = sshString("rsa-sha2-256".toByteArray()) +
            sshString(ByteArray(60) + raw)
        assertArrayEquals(expected, out)
    }

    @Test
    fun ecdsaP256SignatureMapsToPointForm() {
        val r = ByteArray(32) { 0x11 }; val s = ByteArray(32) { 0x22 }
        val line = PgpSshBridge.parsePublicKeyLine(
            "ecdsa-sha2-nistp256 " + java.util.Base64.getEncoder().encodeToString(
                sshString("ecdsa-sha2-nistp256".toByteArray()) +
                    sshString("nistp256".toByteArray()) + sshString(byteArrayOf(4) + ByteArray(64))
            ))
        val out = PgpSshBridge.openPgpToSshSignature(armor(packet(sigBody(19, 8, r, s))), line)
        val expected = sshString("ecdsa-sha2-nistp256".toByteArray()) +
            sshString(byteArrayOf(4) + r + s)
        assertArrayEquals(expected, out)
    }

    @Test
    fun ed25519SignatureMapsToRAndS() {
        val r = ByteArray(32) { 0x33 }; val s = ByteArray(32) { 0x44 }
        val line = PgpSshBridge.parsePublicKeyLine("ssh-ed25519 " +
            java.util.Base64.getEncoder().encodeToString(
                sshString("ssh-ed25519".toByteArray()) + sshString(ByteArray(32))) + " c")
        val out = PgpSshBridge.openPgpToSshSignature(armor(packet(sigBody(22, 8, r, s))), line)
        val expected = sshString("ssh-ed25519".toByteArray()) +
            sshString(r + s)
        assertArrayEquals(expected, out)
    }

    @Test
    fun sha512HashMapsToRsaSha2_512() {
        val raw = ByteArray(64) { 7 }
        val line = PgpSshBridge.parsePublicKeyLine(
            "ssh-rsa " + java.util.Base64.getEncoder().encodeToString(
                sshString("ssh-rsa".toByteArray()) + sshString(byteArrayOf(1, 0, 1)) +
                    sshString(ByteArray(64))
            ))
        val out = PgpSshBridge.openPgpToSshSignature(armor(packet(sigBody(1, 10, raw))), line)
        val expected = sshString("rsa-sha2-512".toByteArray()) + sshString(raw)
        assertArrayEquals(expected, out)
    }

    @Test
    fun rejectsHashAlgorithmMismatch() {
        val line = PgpSshBridge.parsePublicKeyLine(
            "ecdsa-sha2-nistp256 " + java.util.Base64.getEncoder().encodeToString(
                sshString("ecdsa-sha2-nistp256".toByteArray()) +
                    sshString("nistp256".toByteArray()) + sshString(byteArrayOf(4) + ByteArray(64))
            ))
        // SHA-512 (10) on a nistp256 key → rejected
        try {
            PgpSshBridge.openPgpToSshSignature(armor(packet(sigBody(19, 10, ByteArray(32), ByteArray(32)))), line)
            throw AssertionError("expected rejection")
        } catch (e: PgpSshBridge.PgpSshBridgeException) {
            assertTrue(e.message!!.contains("SHA-256"))
        }
    }

    @Test
    fun rejectsPublicKeyLineMismatch() {
        val line = PgpSshBridge.parsePublicKeyLine("ssh-rsa " +
            java.util.Base64.getEncoder().encodeToString(
                sshString("ssh-rsa".toByteArray()) + sshString(byteArrayOf(1, 0, 1)) +
                    sshString(ByteArray(64))))
        try {
            PgpSshBridge.openPgpToSshSignature(
                armor(packet(sigBody(19, 8, ByteArray(32), ByteArray(32)))), line)
            throw AssertionError("expected rejection")
        } catch (e: PgpSshBridge.PgpSshBridgeException) {
            assertTrue(e.message!!.contains("mismatch"))
        }
    }

    // -- key material → SSH line ----------------------------------------------

    /** Builds a v4 public-SUBKEY packet body: version, creation time, alg,
     *  then the alg-specific MPIs (RSA: n, e). */
    private fun rsaPubkeyBody(n: ByteArray, e: ByteArray): ByteArray =
        byteArrayOf(4) +
            byteArrayOf(0, 0, 0, 1) +   // creation time
            1.toByte() +                 // RSA
            mpi(n) + mpi(e)

    @Test
    fun keyMaterialBuildsOpenSshLine() {
        val n = ByteArray(64) { 0xAB.toByte() }  // 512-bit test modulus
        n[0] = 0xC0.toByte()                     // set the high bits (realistic)
        val e = byteArrayOf(1, 0, 1)
        val body = rsaPubkeyBody(n, e)

        // v4 fingerprint: SHA-1(0x99 || u16(len) || body) → the key id = fp[-8..]
        val fpInput = byteArrayOf(0x99.toByte()) +
            byteArrayOf(((body.size ushr 8) and 0xFF).toByte(), (body.size and 0xFF).toByte()) + body
        val sha1 = java.security.MessageDigest.getInstance("SHA-1").digest(fpInput)
        val keyId = (0 until 8).fold(0L) { acc, k ->
            (acc shl 8) or (sha1[sha1.size - 8 + k].toLong() and 0xFF)
        }

        // The armored keyring: the KEY packet + the SUBKEY packet.
        val keyBody = byteArrayOf(4) + byteArrayOf(0, 0, 0, 1) + 1.toByte() + mpi(n) + mpi(e)
        // New-format tag 14 (public subkey), 1-octet length (77 < 192).
        val subkeyPkt = byteArrayOf(0xCE.toByte(), keyBody.size.toByte()) + keyBody
        val keyPkt = byteArrayOf(0x99.toByte()) + u16(keyBody.size) + keyBody
        val keyring = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            java.util.Base64.getEncoder().encodeToString(keyPkt + subkeyPkt) +
            "\n-----END PGP PUBLIC KEY BLOCK-----\n"

        val line = PgpSshBridge.sshLineForKeyMaterial(keyring, keyId, "offlinepass-test")

        val parts = line.split(" ")
        assertEquals("ssh-rsa", parts[0])
        assertEquals("offlinepass-test", parts[2])
        // The blob: string("ssh-rsa") + SSH mpints — 4-byte byte-length
        // strings (unlike the OpenPGP MPI's 2-byte BIT-length form).
        val blob = java.util.Base64.getDecoder().decode(parts[1])
        val algStr = sshString("ssh-rsa".toByteArray())
        assertArrayEquals(algStr, blob.copyOfRange(0, algStr.size))
        // e: SSH mpint of 65537
        val eMpi = sshString(e)
        assertArrayEquals(eMpi, blob.copyOfRange(algStr.size, algStr.size + eMpi.size))
        // n: SSH mpint of the 64-byte modulus
        val nMpi = sshString(n)
        assertArrayEquals(nMpi, blob.copyOfRange(blob.size - nMpi.size, blob.size))
        assertEquals(algStr.size + eMpi.size + nMpi.size, blob.size)
    }
}
