package com.offlinepass.app.crypto

import java.math.BigInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature

/**
 * THE Ed25519 COMMIT-SIGNATURE PATH (PgpSigBuilder alg 22): the card's
 * PureEdDSA over the FULL SIGNED MATERIAL (content||prefix||trailer —
 * NOT a digest, NOT a DigestInfo), the raw 64-byte R||S out, the packet
 * body = MPI(R)||MPI(S) under pubkey alg 22 / hash alg 8 (SHA-256 — the
 * v4 EdDSA's only legal hash; used for the left-16-bits confirmation).
 *
 * The "card" = the JVM's real Ed25519 (java.security.Signature — the
 * same primitive the applet runs), so the round-trip is a REAL
 * verification, not a shape check.
 */
class PgpSigBuilderEd25519Test {

    private val kp: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    private val content = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
        "parent 1234567890abcdef1234567890abcdef12345678\n" +
        "author offlinepass-android <offlinepass@android.local> 1700000000 +0000\n"

    /** The "card": PureEdDSA over the SHA-256 DIGEST (the OpenPGP card
     *  spec's EdDSA PSO:CDS — the host hashes, the card signs the
     *  digest). The handed digest is captured for the input pin. */
    private var cardInput: ByteArray? = null

    private fun cardSign(handed: ByteArray): ByteArray {
        cardInput = handed // what the builder handed: the 32-byte digest
        val s = Signature.getInstance("Ed25519")
        s.initSign(kp.private)
        s.update(handed)
        return s.sign() // the raw 64-byte R||S
    }

    /** The v4 signed material: content || prefix || trailer. */
    private fun expectedMaterial(content: ByteArray, packet: ByteArray): ByteArray {
        // The prefix = the packet's body head through the hashed
        // subpackets. The new-format header's length is 1 octet < 192
        // (our small body) — parse, don't assume.
        val body = packet.copyOfRange(2, packet.size)
        val hashedLen = ((body[4].toInt() and 0xFF) shl 8) or (body[5].toInt() and 0xFF)
        val prefixLen = 4 + 2 + hashedLen
        val prefix = body.copyOfRange(0, prefixLen)
        return content + prefix +
            (byteArrayOf(4, 0xFF.toByte()) +
                byteArrayOf(((prefixLen ushr 24) and 0xFF).toByte(),
                    ((prefixLen ushr 16) and 0xFF).toByte(),
                    ((prefixLen ushr 8) and 0xFF).toByte(),
                    (prefixLen and 0xFF).toByte()))
    }

    @Test
    fun `the packet is alg-22 sha-256 with the R-S MPIs and REALLY verifies`() {
        val keyId = 0x123456789ABCDEFL
        val packet = PgpSigBuilder.detachedSignature(
            content.toByteArray(), keyId, createdAt = 1700000000,
            sign = { material -> cardSign(material) },
            pubkeyAlg = PgpSigBuilder.PUB_ALG_ED25519)

        // The packet header + the fixed fields.
        assertEquals(0xC2, packet[0].toInt() and 0xFF) // the new-format tag 2
        val body = packet.copyOfRange(2, packet.size) // 1-octet len < 192
        assertEquals(4, body[0].toInt()) // the v4
        assertEquals(0, body[1].toInt()) // the binary sig type
        assertEquals(22, body[2].toInt()) // THE EdDSA pubkey alg
        assertEquals(8, body[3].toInt()) // SHA-256

        // THE INPUT PIN: the card got the RAW SHA-256 DIGEST of the
        // signed material (the card-spec EdDSA: the host hashes, the
        // card PureEdDSAs the 32-byte digest — NOT a DigestInfo, NOT
        // the material).
        val material = expectedMaterial(content.toByteArray(), packet)
        val md = java.security.MessageDigest.getInstance("SHA-256")
        assertArrayEquals("the card must see the material's SHA-256 digest",
            md.digest(material), cardInput)

        // Parse the body properly: prefix || unhashed || left-16-bits ||
        // MPI(R) || MPI(S).
        var p = 4 + 2 + ((body[4].toInt() and 0xFF) shl 8 or (body[5].toInt() and 0xFF))
        val unhashedLen = (body[p].toInt() and 0xFF) shl 8 or (body[p + 1].toInt() and 0xFF)
        p += 2 + unhashedLen
        p += 2 // the digest's left-16-bits (the confirmation)
        fun readMpi(): ByteArray {
            val bits = (body[p].toInt() and 0xFF) shl 8 or (body[p + 1].toInt() and 0xFF)
            val len = (bits + 7) / 8
            return body.copyOfRange(p + 2, p + 2 + len).also { p += 2 + len }
        }
        val r = readMpi()
        val s = readMpi()
        assertEquals("the packet ends after MPI(S)", body.size, p)

        // THE REAL VERIFICATION: R||S over the DIGEST with the real key.
        val v = Signature.getInstance("Ed25519")
        v.initVerify(kp.public)
        v.update(md.digest(material))
        org.junit.Assert.assertTrue(
            "the R||S over the digest must verify with the real key",
            v.verify(r + s))
    }

    @Test
    fun `a wrong-size card answer is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            PgpSigBuilder.detachedSignature(
                content.toByteArray(), 1L, 1700000000,
                sign = { ByteArray(32) }, // not the 64-byte R||S
                pubkeyAlg = PgpSigBuilder.PUB_ALG_ED25519)
        }
    }

    @Test
    fun `the v4 EdDSA refuses a non-SHA256 hash`() {
        assertThrows(IllegalArgumentException::class.java) {
            PgpSigBuilder.detachedSignature(
                content.toByteArray(), 1L, 1700000000,
                sign = { ByteArray(64) },
                pubkeyAlg = PgpSigBuilder.PUB_ALG_ED25519,
                hashAlg = 10) // SHA-512: illegal for the v4 EdDSA
        }
    }

    @Test
    fun `the armored block round-trips through the BouncyCastle verifier`() {
        // THE STRONGEST CHECK: the same BC PGPSignature path gpg-likes
        // verify with — BC 1.87 speaks the native Ed25519 tags.
        java.security.Security.addProvider(
            org.bouncycastle.jce.provider.BouncyCastleProvider())
        val packet = PgpSigBuilder.detachedSignature(
            content.toByteArray(), 0x123456789ABCDEFL, 1700000000,
            sign = { cardSign(it) },
            pubkeyAlg = PgpSigBuilder.PUB_ALG_ED25519)
        val armored = PgpSigBuilder.armoredSignature(packet)

        val decoded = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(
            armored.byteInputStream())
        val factory = org.bouncycastle.openpgp.PGPObjectFactory(
            decoded, org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator())
        val sig = (factory.nextObject() as org.bouncycastle.openpgp.PGPSignatureList)[0]
        val pk = org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter()
            .getPGPPublicKey(org.bouncycastle.bcpg.PublicKeyAlgorithmTags.EDDSA,
                kp.public, java.util.Date())
        sig.init(
            org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider()
                .setProvider("BC"), pk)
        sig.update(content.toByteArray())
        assertTrue("BC must verify the Ed25519 detached signature",
            sig.verify())
    }

    // -- THE MPI BOUNDARY VECTORS (deterministic, no random keys) ----------

    /** Parses the packet body's two trailing MPIs. */
    private fun parseTailMpis(body: ByteArray): Pair<ByteArray, ByteArray> {
        var p = 4 + 2 + ((body[4].toInt() and 0xFF) shl 8 or (body[5].toInt() and 0xFF))
        val unhashedLen = (body[p].toInt() and 0xFF) shl 8 or (body[p + 1].toInt() and 0xFF)
        p += 2 + unhashedLen + 2 // + the digest's left-16-bits
        fun readMpi(): ByteArray {
            val bits = (body[p].toInt() and 0xFF) shl 8 or (body[p + 1].toInt() and 0xFF)
            val len = (bits + 7) / 8
            return body.copyOfRange(p + 2, p + 2 + len).also { p += 2 + len }
        }
        val r = readMpi()
        return r to readMpi()
    }

    private fun buildWithCard(raw64: ByteArray): ByteArray =
        PgpSigBuilder.detachedSignature(
            content.toByteArray(), 1L, 1700000000,
            sign = { raw64 }, pubkeyAlg = PgpSigBuilder.PUB_ALG_ED25519)

    @Test
    fun `MPI edge - the values with the high bit CLEAR encode at 255 bits (no padding)`() {
        // R = 0x7f.. (the top bit clear = 255 bits, 32 bytes), S likewise.
        val raw = ByteArray(64) { 0x42 }
        raw[0] = 0x7f; raw[32] = 0x7f
        val packet = buildWithCard(raw)
        val (r, s) = parseTailMpis(packet.copyOfRange(2, packet.size))
        assertEquals(255, BigInteger(1, r).bitLength())
        assertEquals(255, BigInteger(1, s).bitLength())
        assertEquals(32, r.size)
        assertArrayEquals(raw.copyOfRange(0, 32), r)
        assertArrayEquals(raw.copyOfRange(32, 64), s)
    }

    @Test
    fun `MPI edge - the leading zero bytes in R and S are stripped (minimal encoding)`() {
        // The OpenPGP MPI = minimal big-endian: the leading zero octets
        // drop (a REAL occurrence: Ed25519's R/S are uniform — 1/256
        // start 0x00, 1/65536 start 0x0000). The VALUE must survive.
        val raw = ByteArray(64) { 0x00 }
        raw[31] = 0x03                          // R = 3 (a 2-bit value)
        raw[63] = 0x02                          // S = 2 (a 2-bit value)
        val packet = buildWithCard(raw)
        val (r, s) = parseTailMpis(packet.copyOfRange(2, packet.size))
        assertEquals(BigInteger(1, raw.copyOfRange(0, 32)), BigInteger(1, r))
        assertEquals(BigInteger(1, raw.copyOfRange(32, 64)), BigInteger(1, s))
        assertEquals(1, r.size)
        assertEquals(1, s.size)
    }

    // -- THE PACKET-LENGTH ENCODER'S THREE BRANCHES (RFC 4880 §4.2.2) ------

    @Test
    fun `the length encoder - 1-octet, 2-octet, and 5-octet branches`() {
        fun bodyOf(n: Int) = ByteArray(n) { (it % 251).toByte() }

        // < 192: the 1-octet length.
        val small = PgpSigBuilder.packet(2, bodyOf(100))
        assertEquals(0xC2, small[0].toInt() and 0xFF)
        assertEquals(100, small[1].toInt() and 0xFF)
        assertEquals(102, small.size) // tag(1) + len(1) + body(100)

        // 192..8383: the 2-octet form — the body's length = the encoded
        // 16-bit value + 192.
        val mid = PgpSigBuilder.packet(2, bodyOf(1000))
        assertEquals(0xC2, mid[0].toInt() and 0xFF)
        // RFC 4880 §4.2.2: the length = ((o1 - 192) << 8) + o2 + 192.
        val midLen = (((mid[1].toInt() and 0xFF) - 192) shl 8 or (mid[2].toInt() and 0xFF)) + 192
        assertEquals(1000, midLen)
        assertEquals(1003, mid.size) // tag(1) + len(2) + body(1000)

        // 192 exactly = the 2-octet boundary (the minimal 2-octet body).
        val boundary = PgpSigBuilder.packet(2, bodyOf(192))
        assertEquals(192, (((boundary[1].toInt() and 0xFF) - 192) shl 8 or
            (boundary[2].toInt() and 0xFF)) + 192)
        assertEquals(195, boundary.size) // tag(1) + len(2) + body(192)

        // > 8383: the 5-octet form (255 + u32).
        val big = PgpSigBuilder.packet(2, bodyOf(9000))
        assertEquals(255, big[1].toInt() and 0xFF)
        val bigLen = ((big[2].toInt() and 0xFF) shl 24) or ((big[3].toInt() and 0xFF) shl 16) or
            ((big[4].toInt() and 0xFF) shl 8) or (big[5].toInt() and 0xFF)
        assertEquals(9000, bigLen)
        assertEquals(9006, big.size) // tag(1) + len(5) + body(9000)
    }
}
