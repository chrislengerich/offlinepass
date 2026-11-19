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

    /** A v4 signature packet body: version, type, pubkeyAlg, hashAlg, hashed
     *  subpackets, empty unhashed area, then the given MPIs. */
    private fun sigBody(pubkeyAlg: Int, hashAlg: Int, vararg mpis: ByteArray): ByteArray {
        return sigBodySubpackets(pubkeyAlg, hashAlg, hashed = ByteArray(0), mpis = mpis)
    }

    /** Same, with a KEY FLAGS subpacket in the hashed area. */
    private fun sigBodyWithFlags(pubkeyAlg: Int, hashAlg: Int, keyFlags: Int, vararg mpis: ByteArray): ByteArray {
        val hashed = byteArrayOf(2, 27, keyFlags.toByte())
        return sigBodySubpackets(pubkeyAlg, hashAlg, hashed, mpis)
    }

    private fun sigBodySubpackets(
        pubkeyAlg: Int, hashAlg: Int, hashed: ByteArray, mpis: Array<out ByteArray>
    ): ByteArray {
        val mpiBytes = mpis.flatMap { m -> mpi(m).toList() }.toByteArray()
        return byteArrayOf(4, 0, pubkeyAlg.toByte(), hashAlg.toByte()) +
            u16(hashed.size) + hashed + u16(0) + mpiBytes
    }

    /** A v4 public-key/subkey packet body: version, creation time, alg,
     *  RSA MPIs (n, e). */
    private fun pubkeyBody(n: ByteArray, e: ByteArray): ByteArray =
        byteArrayOf(4, 0, 0, 0, 1) + mpi(n) + mpi(e)

    private fun keyIdOf(pubBody: ByteArray): Long {
        val fpInput = byteArrayOf(0x99.toByte()) + u16(pubBody.size) + pubBody
        val sha1 = java.security.MessageDigest.getInstance("SHA-1").digest(fpInput)
        return (0 until 8).fold(0L) { acc, k ->
            (acc shl 8) or (sha1[sha1.size - 8 + k].toLong() and 0xFF)
        }
    }

    /** Generic packet wrapper (tag + new-format length). */
    private fun pkt(tag: Int, body: ByteArray): ByteArray {
        val lenEnc = when {
            body.size < 192 -> byteArrayOf(body.size.toByte())
            body.size <= 8383 -> {
                val n = body.size - 192
                byteArrayOf(((n ushr 8) + 192).toByte(), (n and 0xFF).toByte())
            }
            else -> byteArrayOf(255.toByte()) + u16(body.size ushr 16) + u16(body.size and 0xFFFF)
        }
        val tagByte = (0xC0 or tag).toByte()
        return byteArrayOf(tagByte) + lenEnc + body
    }

    /** A keyring: primary [CE] + a signing subkey + a non-signing subkey,
     *  each with its self-signature carrying key flags. */
    private fun keyring(sub1Flags: Int?, sub2Flags: Int?, primaryFlags: Int? = 0x01): ByteArray {
        val sub1 = pubkeyBody(byteArrayOf(1, 2, 3), byteArrayOf(1, 0, 1))
        val sub2 = pubkeyBody(byteArrayOf(4, 5, 6), byteArrayOf(1, 0, 1))
        val primary = pubkeyBody(byteArrayOf(9, 9, 9), byteArrayOf(1, 0, 1))
        fun sig(flags: Int?) = if (flags == null) pkt(2, sigBody(1, 8))
            else pkt(2, sigBodyWithFlags(1, 8, flags))
        val sig1 = sig(sub1Flags)
        val sig2 = sig(sub2Flags)
        val sigP = sig(primaryFlags)
        return pkt(6, primary) + sigP + pkt(14, sub1) + sig1 + pkt(14, sub2) + sig2
    }

    @Test
    fun signingSubkeyPrefersPreferredWhenSignCapable() {
        val keyring = keyring(sub1Flags = 0x02, sub2Flags = 0x04)
        val data = java.util.Base64.getEncoder().encodeToString(keyring)
        val sub1Id = keyIdOf(pubkeyBody(byteArrayOf(1, 2, 3), byteArrayOf(1, 0, 1)))
        assertEquals(sub1Id, PgpSshBridge.signingSubkeyKeyId(data, sub1Id))
    }

    @Test
    fun signingSubkeyResolvesWhenPreferredCantSign() {
        val keyring = keyring(sub1Flags = 0x02, sub2Flags = 0x04)
        val data = java.util.Base64.getEncoder().encodeToString(keyring)
        val sub1Id = keyIdOf(pubkeyBody(byteArrayOf(1, 2, 3), byteArrayOf(1, 0, 1)))
        // The "preferred" (what the picker handed back) can't sign → resolve.
        assertEquals(sub1Id, PgpSshBridge.signingSubkeyKeyId(data, 12345L))
    }

    @Test
    fun signingSubkeyReturnsNullWhenNothingCanSign() {
        val keyring = keyring(sub1Flags = 0x04, sub2Flags = 0x20)
        val data = java.util.Base64.getEncoder().encodeToString(keyring)
        assertEquals(null, PgpSshBridge.signingSubkeyKeyId(data, null))
    }

    @Test
    fun signingSubkeyWithoutFlagsAssumesCapable() {
        // RFC 4880: an absent KEY FLAGS subpacket means all capabilities.
        val keyring = keyring(sub1Flags = null, sub2Flags = null)
        val data = java.util.Base64.getEncoder().encodeToString(keyring)
        val sub2Id = keyIdOf(pubkeyBody(byteArrayOf(4, 5, 6), byteArrayOf(1, 0, 1)))
        assertEquals(sub2Id, PgpSshBridge.signingSubkeyKeyId(data, sub2Id))
    }

    @Test
    fun signingSubkeyUnionsMultipleSelfSignatures() {
        // First self-sig without flags, later one grants sign.
        val sub1 = pubkeyBody(byteArrayOf(1, 2, 3), byteArrayOf(1, 0, 1))
        val sub1Id = keyIdOf(sub1)
        val primary = pubkeyBody(byteArrayOf(9, 9, 9), byteArrayOf(1, 0, 1))
        val data = java.util.Base64.getEncoder().encodeToString(
            pkt(6, primary) +
            pkt(2, sigBodyWithFlags(1, 8, 0x01)) +  // primary: certify only
            pkt(14, sub1) +
            pkt(2, sigBody(1, 8)) +
            pkt(2, sigBodyWithFlags(1, 8, 0x02))    // sub1: sign granted later
        )
        assertEquals(sub1Id, PgpSshBridge.signingSubkeyKeyId(data, null))
    }

    private fun newFormatPacket(tag: Int, body: ByteArray): ByteArray {
        val n = body.size - 192
        val lenEnc = byteArrayOf(((n ushr 8) + 192).toByte(), (n and 0xFF).toByte())
        return byteArrayOf((0xC0 or tag).toByte()) + lenEnc + body
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
    fun oldFormatSignatureHeaderParses() {
        // gpg/OKK emit OLD-format packet headers (0x88-style) — the parser
        // must accept them alongside new-format ones.
        val raw = ByteArray(8) { (it + 1).toByte() }
        val body = byteArrayOf(4, 0, 1, 8) + u16(0) + u16(0) + mpi(raw)
        val packet = byteArrayOf(0x88.toByte()) + byteArrayOf(body.size.toByte()) + body
        val line = PgpSshBridge.parsePublicKeyLine(
            "ssh-rsa " + java.util.Base64.getEncoder().encodeToString(
                sshString("ssh-rsa".toByteArray()) + sshString(byteArrayOf(1, 0, 1)) +
                    sshString(ByteArray(64))) + " c")
        val out = PgpSshBridge.openPgpToSshSignature(armor(packet), line)
        val expected = sshString("rsa-sha2-256".toByteArray()) +
            sshString(ByteArray(56) + raw)
        assertArrayEquals(expected, out)
    }

    @Test
    fun newFormatTwoOctetLengthParses() {
        // BouncyCastle emits TWO-OCTET new-format lengths for big packets —
        // a precedence bug mis-parsed them (the +192 was applied to the
        // wrong operand) and the RSA MPI read ran off the body.
        val raw = ByteArray(64) { (it * 3).toByte() }
        val body = byteArrayOf(4, 0, 1, 8) + u16(0) + u16(0) + mpi(raw)
        // force the 2-octet encoding: pad the length region with a large
        // enough body
        val padded = body + ByteArray(300)  // body.size now > 191
        val packet = newFormatPacket(2, padded)
        val line = PgpSshBridge.parsePublicKeyLine(
            "ssh-rsa " + java.util.Base64.getEncoder().encodeToString(
                sshString("ssh-rsa".toByteArray()) + sshString(byteArrayOf(1, 0, 1)) +
                    sshString(ByteArray(64))) + " c")
        val out = PgpSshBridge.openPgpToSshSignature(armor(packet), line)
        // raw is exactly modulus-sized: no padding added
        val expected = sshString("rsa-sha2-256".toByteArray()) + sshString(raw)
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
        // n: SSH mpint of the 64-byte modulus — canonical (0xC0 sets the
        // high bit → the leading 0x00 sign byte is REQUIRED, RFC 4251 §5).
        val nMpi = sshString(byteArrayOf(0x00) + n)
        assertArrayEquals(nMpi, blob.copyOfRange(blob.size - nMpi.size, blob.size))
        assertEquals(algStr.size + eMpi.size + nMpi.size, blob.size)
    }
    // -- The AUTH-capable subkey resolution (the YubiKey mode) ---------------

    @Test
    fun authSubkeyResolvesWhenPreferredCantAuth() {
        // 0x20 = the authenticate flag; the sub1 holds sign only.
        val keyring = keyring(sub1Flags = 0x02, sub2Flags = 0x20)
        val data = java.util.Base64.getEncoder().encodeToString(keyring)
        val sub2Id = keyIdOf(pubkeyBody(byteArrayOf(4, 5, 6), byteArrayOf(1, 0, 1)))
        assertEquals(sub2Id, PgpSshBridge.authSubkeyKeyId(data, 12345L))
    }

    @Test
    fun authSubkeyPrefersPreferredWhenAuthCapable() {
        val keyring = keyring(sub1Flags = 0x20, sub2Flags = 0x02)
        val data = java.util.Base64.getEncoder().encodeToString(keyring)
        val sub1Id = keyIdOf(pubkeyBody(byteArrayOf(1, 2, 3), byteArrayOf(1, 0, 1)))
        assertEquals(sub1Id, PgpSshBridge.authSubkeyKeyId(data, sub1Id))
    }

    @Test
    fun authSubkeyReturnsNullWhenNothingCanAuth() {
        val keyring = keyring(sub1Flags = 0x02, sub2Flags = 0x04)
        val data = java.util.Base64.getEncoder().encodeToString(keyring)
        assertEquals(null, PgpSshBridge.authSubkeyKeyId(data, null))
    }

    // -- Canonical ssh-rsa mpints (the sign-byte rule) ------------------------

    @Test
    fun rsaBlobCarriesTheSignByteForHighBitModuli() {
        // A modulus whose first byte has the high bit set — like the real
        // RSA-4096 subkey measured on-device (n starting 0xc6) — MUST get
        // the leading 0x00 mpint sign byte in the SSH blob (RFC 4251 §5);
        // OpenPGP MPIs strip it, and the non-canonical blob parses as a
        // NEGATIVE modulus (strict parsers reject the offer).
        val n = byteArrayOf(0xC6.toByte(), 0x01, 0x02, 0x03)  // high bit set
        val e = byteArrayOf(0x01, 0x00, 0x01)
        val sub = rsaPubkeyBody(n, e)
        val subId = keyIdOf(sub)
        val primary = pubkeyBody(byteArrayOf(9, 9, 9), byteArrayOf(1, 0, 1))
        val keyring = java.util.Base64.getEncoder().encodeToString(
            pkt(6, primary) + pkt(2, sigBodyWithFlags(1, 8, 0x01)) +
            pkt(14, sub) + pkt(2, sigBodyWithFlags(1, 8, 0x20)))
        val armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + keyring +
            "\n-----END PGP PUBLIC KEY BLOCK-----"
        val line = PgpSshBridge.sshLineForKeyMaterial(armored, subId, "t")
        val blob = java.util.Base64.getDecoder().decode(line.split(" ")[1])
        // string("ssh-rsa") + string(e) + string(n): e needs no sign byte,
        // n (0xC6…) MUST be 5 bytes with the leading 0x00.
        var p = 0
        fun str(): ByteArray {
            val len = ((blob[p].toInt() and 0xFF) shl 24) or ((blob[p+1].toInt() and 0xFF) shl 16) or
                ((blob[p+2].toInt() and 0xFF) shl 8) or (blob[p+3].toInt() and 0xFF)
            val v = blob.copyOfRange(p + 4, p + 4 + len); p += 4 + len; return v
        }
        assertArrayEquals("ssh-rsa".toByteArray(), str())
        assertArrayEquals(e, str())
        val nWire = str()
        assertEquals(5, nWire.size)
        assertEquals(0x00.toByte(), nWire[0])
        assertArrayEquals(n, nWire.copyOfRange(1, 5))
    }

    @org.junit.Test
    fun `rsaSshLine round-trips through parse and fingerprint`() {
        val n = java.math.BigInteger(1, byteArrayOf(
            0xC6.toByte(), 0x11, 0x7F.toByte(), 0x33, 0x44))
        val e = java.math.BigInteger(1, byteArrayOf(0x01, 0x00, 0x01))
        val line = PgpSshBridge.rsaSshLine(n, e, "offlinepass-test")
        val parsed = PgpSshBridge.parsePublicKeyLine(line)
        assertEquals("ssh-rsa", parsed.algorithm)
        assertEquals("offlinepass-test", parsed.comment)
        // The line's fingerprint = the live-key fingerprint — the same
        // wire construction under both.
        assertEquals(PgpSshBridge.rsaFingerprint(n, e),
            PgpSshBridge.fingerprintOf(line))
        // And the blank-comment form stays pasteable (no trailing space).
        assertTrue(!PgpSshBridge.rsaSshLine(n, e, "").endsWith(" "))
    }

    @org.junit.Test
    fun `ecSshLine round-trips and fingerprints like the enrolled form`() {
        val ekp = java.security.KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val pub = ekp.public as java.security.interfaces.ECPublicKey
        fun pad(v: java.math.BigInteger, n: Int): ByteArray {
            val b = v.toByteArray()
            val body = if (b.size > n) b.copyOfRange(b.size - n, b.size) else b
            return ByteArray(n - body.size) + body
        }
        val point = byteArrayOf(0x04) + pad(pub.w.affineX, 32) + pad(pub.w.affineY, 32)
        val line = PgpSshBridge.ecSshLine("nistp256", point, "offlinepass-test")
        val parsed = PgpSshBridge.parsePublicKeyLine(line)
        assertEquals("ecdsa-sha2-nistp256", parsed.algorithm)
        assertEquals("offlinepass-test", parsed.comment)
        assertEquals(
            PgpSshBridge.ecFingerprint("nistp256", point),
            PgpSshBridge.fingerprintOf(line))
        // The parsed line yields a JCE key that verifies the card's DER.
        val jcePub = PgpSshBridge.publicKeyFromLine(parsed)
        val data = "offlinepass ec sig slot".toByteArray()
        val der = java.security.Signature.getInstance("SHA256withECDSA").apply {
            initSign(ekp.private); update(data)
        }.sign()
        assertTrue(java.security.Signature.getInstance("SHA256withECDSA").apply {
            initVerify(jcePub); update(data)
        }.verify(der))
    }

    @org.junit.Test
    fun `ecdsaSshSigValue converts a real DER signature and verifies back`() {
        val kp = java.security.KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val data = "offlinepass ec round trip".toByteArray()
        val der = java.security.Signature.getInstance("SHA256withECDSA").apply {
            initSign(kp.private); update(data)
        }.sign()
        // The SSH value: string(r) + string(s) — each a 4-byte length
        // prefix + the 32-byte padded half (36 + 36 = 72).
        val value = PgpSshBridge.ecdsaSshSigValue(der, 32)
        org.junit.Assert.assertEquals(72, value.size)
        fun str(b: ByteArray, p0: Int): Pair<ByteArray, Int> {
            val len = ((b[p0].toInt() and 0xFF) shl 24) or ((b[p0 + 1].toInt() and 0xFF) shl 16) or
                ((b[p0 + 2].toInt() and 0xFF) shl 8) or (b[p0 + 3].toInt() and 0xFF)
            return b.copyOfRange(p0 + 4, p0 + 4 + len) to (p0 + 4 + len)
        }
        val (rRaw, p2) = str(value, 0)
        val (sRaw, _) = str(value, p2)
        org.junit.Assert.assertEquals(32, rRaw.size)
        org.junit.Assert.assertEquals(32, sRaw.size)
        // Rebuild a DER from the SSH halves — the round-trip closes with
        // a JCE verification against the original data.
        fun big(v: ByteArray) = java.math.BigInteger(1, v)
        val r = big(rRaw)
        val s = big(sRaw)
        fun int(v: java.math.BigInteger): ByteArray {
            val b = v.toByteArray()
            return byteArrayOf(0x02, b.size.toByte()) + b
        }
        val body = int(r) + int(s)
        val der2 = byteArrayOf(0x30, body.size.toByte()) + body
        org.junit.Assert.assertTrue(
            java.security.Signature.getInstance("SHA256withECDSA").apply {
                initVerify(kp.public); update(data)
            }.verify(der2))
    }

    @org.junit.Test
    fun `publicKeyFromLine verifies an ECDSA signature`() {
        val kp = java.security.KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val pub = kp.public as java.security.interfaces.ECPublicKey
        fun pad32(v: java.math.BigInteger): ByteArray {
            val b = v.toByteArray()
            val body = if (b.size > 32) b.copyOfRange(b.size - 32, b.size) else b
            return ByteArray(32 - body.size) + body
        }
        val point = byteArrayOf(0x04) + pad32(pub.w.affineX) + pad32(pub.w.affineY)
        fun ss(b: ByteArray) = byteArrayOf(
            ((b.size ushr 24) and 0xFF).toByte(), ((b.size ushr 16) and 0xFF).toByte(),
            ((b.size ushr 8) and 0xFF).toByte(), (b.size and 0xFF).toByte()) + b
        val blob = ss("ecdsa-sha2-nistp256".toByteArray()) +
            ss("nistp256".toByteArray()) + ss(point)
        val line = "ecdsa-sha2-nistp256 " +
            java.util.Base64.getEncoder().encodeToString(blob) + " card"
        val jcePub = PgpSshBridge.publicKeyFromLine(PgpSshBridge.parsePublicKeyLine(line))
        val data = "offlinepass ec verify".toByteArray()
        val der = java.security.Signature.getInstance("SHA256withECDSA").apply {
            initSign(kp.private); update(data)
        }.sign()
        org.junit.Assert.assertTrue(
            java.security.Signature.getInstance("SHA256withECDSA").apply {
                initVerify(jcePub); update(data)
            }.verify(der))
    }

    @org.junit.Test
    fun `rsaFingerprint matches the enrolled line's fingerprint`() {
        // The live-card read (modulus + exponent BigIntegers) must produce
        // the SAME "SHA256:…" fingerprint as the enrolled SSH line — the
        // auth-log's which-key comparison depends on it.
        val n = java.math.BigInteger(1, byteArrayOf(
            0xC6.toByte(), 0x11, 0x7F.toByte(), 0x33, 0x44))
        val e = java.math.BigInteger(1, byteArrayOf(0x01, 0x00, 0x01))
        val blob = "ssh-rsa " + java.util.Base64.getEncoder().encodeToString(
            // string("ssh-rsa") + mpint(e) + mpint(n) — the wire order.
            run {
                fun s(b: ByteArray) = byteArrayOf(
                    ((b.size ushr 24) and 0xFF).toByte(), ((b.size ushr 16) and 0xFF).toByte(),
                    ((b.size ushr 8) and 0xFF).toByte(), (b.size and 0xFF).toByte()) + b
                fun mpint(v: ByteArray) =
                    if ((v[0].toInt() and 0x80) != 0) byteArrayOf(0) + v else v
                s("ssh-rsa".toByteArray()) + s(mpint(e.toByteArray())) + s(mpint(n.toByteArray()))
            }) + " test"
        assertEquals(
            PgpSshBridge.fingerprintOf(publicKeyLine = blob),
            PgpSshBridge.rsaFingerprint(n, e))
    }

}
