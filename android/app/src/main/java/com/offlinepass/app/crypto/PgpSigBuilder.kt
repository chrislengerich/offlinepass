package com.offlinepass.app.crypto

import java.math.BigInteger

/**
 * Builds a v4 OpenPGP DETACHED SIGNATURE packet over the card's raw
 * signature bytes — the mirror of PgpSshBridge's parsers, which were
 * developed against real gpg output. Used by the YubiKey commit signer.
 * The three card key flavors, each with its own card-input and sig-body:
 *   RSA     — the SHA-256 DigestInfo in, the padded block out (one MPI)
 *   ECDSA   — the raw digest in (the DigestInfo stripped by sign()), the
 *             DER (r, s) out → MPI(r) || MPI(s)
 *   Ed25519 — the SHA-256 DIGEST in (the card PureEdDSAs the digest —
 *             the OpenPGP card spec's EdDSA PSO:CDS is digest-only; the
 *             hash octet = SHA-256 for the left-16-bits confirmation),
 *             the raw 64-byte R||S out → MPI(R)||MPI(S)
 *
 * THE v4 HASH IS NOT THE CONTENT ALONE: RFC 4880 §5.2.4 signs
 * `content || packetPrefix(version..hashed subpackets) || trailer`
 * (trailer = 0x04 0xFF || u32(prefix length)). [detachedSignature] feeds
 * EXACTLY that hash's DigestInfo to the card and assembles the packet
 * from the same prefix — the two agree by construction (measured: a bare
 * content hash FAILS BouncyCastle/gpg verification).
 */
object PgpSigBuilder {

    const val PUB_ALG_RSA = 1
    const val PUB_ALG_ECDSA = 19
    const val PUB_ALG_ED25519 = 22
    const val HASH_SHA256 = 8
    const val SIG_TYPE_BINARY = 0
    const val SUB_CREATION_TIME = 2
    const val SUB_ISSUER_KEY_ID = 16

    /** Builds the full v4 detached-signature packet. [sign] performs the
     *  card op over the pre-built PKCS#1 DigestInfo (the bare DigestInfo —
     *  the card pads on-device) and returns the raw RSA result. */
    fun detachedSignature(
        content: ByteArray,
        keyId: Long,
        createdAt: Int,
        sign: (digestInfo: ByteArray) -> ByteArray,
        sigType: Int = SIG_TYPE_BINARY,
        pubkeyAlg: Int = PUB_ALG_RSA,
        hashAlg: Int = HASH_SHA256,
    ): ByteArray {
        val hashed = subpacket(SUB_CREATION_TIME, u32(createdAt))
        require(pubkeyAlg != PUB_ALG_ED25519 || hashAlg == HASH_SHA256) {
            "the v4 EdDSA signature requires SHA-256 (RFC 4880bis §5.2.3)"
        }
        val prefix = byteArrayOf(4, sigType.toByte(), pubkeyAlg.toByte(), hashAlg.toByte()) +
            u16(hashed.size) + hashed

        // The v4 hash: content || prefix || trailer.
        val md = java.security.MessageDigest.getInstance(hashName(hashAlg))
        md.update(content)
        md.update(prefix)
        md.update(byteArrayOf(4, 0xFF.toByte()) + u32(prefix.size))
        val digest = md.digest()

        // THE CARD'S INPUT FOLLOWS THE ALGORITHM: RSA/ECDSA sign the
        // SHA-256 DigestInfo (the RSA pads on-device; the ECDSA takes the
        // raw digest — sign() strips it). EdDSA (Ed25519): the card
        // PureEdDSAs the RAW SHA-256 DIGEST of the signed material — the
        // OpenPGP card spec's EdDSA PSO:CDS is digest-only (the host
        // hashes; the card treats the 32-byte digest as the Ed25519
        // message — BC's EdDsaSigner does the same in software). The
        // response: RSA = the padded block; ECDSA = the DER (r, s);
        // Ed25519 = the raw 64-byte R||S.
        val raw = when (pubkeyAlg) {
            PUB_ALG_ED25519 -> sign(digest)
            else -> sign(SshRsaPkcs1.digestInfoFromDigest(hashName(hashAlg), digest))
        }
        val unhashed = subpacket(SUB_ISSUER_KEY_ID, u64(keyId))
        // The sig body = the ALGORITHM's: RSA = one MPI (the padded block);
        // ECDSA = MPI(r) || MPI(s) from the card's DER SEQUENCE;
        // Ed25519 = MPI(R) || MPI(S) from the raw 64-byte R||S.
        val sigBody = when (pubkeyAlg) {
            PUB_ALG_ECDSA -> ecdsaMpis(raw)
            PUB_ALG_ED25519 -> ed25519Mpis(raw)
            else -> mpi(raw)
        }
        val body = prefix +
            u16(unhashed.size) + unhashed +
            digest.copyOfRange(0, 2) + sigBody
        return packet(tag = 2, body = body)
    }

    /** The card's Ed25519 output = the raw 64-byte R||S (PureEdDSA over
     *  the digest) — the PGP packet wants the two 32-byte MPIs. */
    private fun ed25519Mpis(raw: ByteArray): ByteArray {
        require(raw.size == 64) {
            "the Ed25519 signature is not the 64-byte R||S (${raw.size}B)"
        }
        return mpi(raw.copyOfRange(0, 32)) + mpi(raw.copyOfRange(32, 64))
    }

    /** The card's ECDSA output = the DER SEQUENCE(INTEGER r, INTEGER s) —
     *  the PGP packet wants the two raw MPIs. */
    private fun ecdsaMpis(der: ByteArray): ByteArray {
        require(der.isNotEmpty() && (der[0].toInt() and 0xFF) == 0x30) {
            "the ECDSA signature is not a DER SEQUENCE"
        }
        var p = 2
        if ((der[1].toInt() and 0x80) != 0) p = 2 + (der[1].toInt() and 0x7F)
        fun readInt(): ByteArray {
            require(p + 2 <= der.size) { "truncated DER INTEGER" }
            val len = der[p + 1].toInt() and 0xFF
            require(p + 2 + len <= der.size) { "truncated DER INTEGER body" }
            val v = der.copyOfRange(p + 2, p + 2 + len)
            p += 2 + len
            return v
        }
        val r = readInt()
        val s = readInt()
        return mpi(r) + mpi(s)
    }

    /** The ASCII armor, byte-identical in shape to gpg's detached
     *  signatures: blank line after the BEGIN marker, base64 wrapped at
     *  64 columns, then the CRC24 checksum line. */
    fun armoredSignature(packet: ByteArray): String {
        val b64 = java.util.Base64.getMimeEncoder(64, "\n".toByteArray())
            .encodeToString(packet)
        val c = crc24(packet)
        val crcB64 = java.util.Base64.getEncoder()
            .encodeToString(byteArrayOf(
                ((c ushr 16) and 0xFF).toByte(),
                ((c ushr 8) and 0xFF).toByte(),
                (c and 0xFF).toByte()))
        return "-----BEGIN PGP SIGNATURE-----\n\n$b64\n=$crcB64\n" +
            "-----END PGP SIGNATURE-----\n"
    }

    /** New-format packet header for tag [tag] with the RFC 4880 §4.2.2
     *  length encodings (1-octet < 192, 2-octet to 8383, 5-octet beyond).
     *  internal: the length-encoder's branches are pinned by test. */
    internal fun packet(tag: Int, body: ByteArray): ByteArray {
        val lenEnc = when {
            body.size < 192 -> byteArrayOf(body.size.toByte())
            body.size <= 8383 -> {
                val n = body.size - 192
                byteArrayOf(((n ushr 8) + 192).toByte(), (n and 0xFF).toByte())
            }
            else -> byteArrayOf(255.toByte()) +
                ((body.size ushr 24) and 0xFF).toByte() +
                ((body.size ushr 16) and 0xFF).toByte() +
                ((body.size ushr 8) and 0xFF).toByte() +
                (body.size and 0xFF).toByte()
        }
        return byteArrayOf((0xC0 or tag).toByte()) + lenEnc + body
    }

    /** One subpacket: 1-octet length (type+body < 192 for ours) + type + body. */
    private fun subpacket(type: Int, body: ByteArray): ByteArray =
        byteArrayOf((body.size + 1).toByte(), type.toByte()) + body

    private fun u16(v: Int): ByteArray = byteArrayOf(
        ((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    private fun u32(v: Int): ByteArray = byteArrayOf(
        ((v ushr 24) and 0xFF).toByte(), ((v ushr 16) and 0xFF).toByte(),
        ((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    private fun u64(v: Long): ByteArray = byteArrayOf(
        ((v ushr 56) and 0xFF).toByte(), ((v ushr 48) and 0xFF).toByte(),
        ((v ushr 40) and 0xFF).toByte(), ((v ushr 32) and 0xFF).toByte(),
        ((v ushr 24) and 0xFF).toByte(), ((v ushr 16) and 0xFF).toByte(),
        ((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    /** The OpenPGP MPI: 2-byte BIT count + minimal big-endian bytes. */
    private fun mpi(v: ByteArray): ByteArray {
        var value = v
        while (value.size > 1 && value[0] == 0x00.toByte()) {
            value = value.copyOfRange(1, value.size)
        }
        val bits = BigInteger(1, value).bitLength()
        val len = (bits + 7) / 8
        val content = value.copyOfRange(value.size - len, value.size)
        return byteArrayOf(((bits ushr 8) and 0xFF).toByte(), (bits and 0xFF).toByte()) + content
    }

    /** RFC 4880 §6.1 CRC-24 (init 0xB704CE, poly 0x864CFB). */
    private fun crc24(data: ByteArray): Int {
        var crc = 0xB704CE
        for (b in data) {
            crc = crc xor ((b.toInt() and 0xFF) shl 16)
            repeat(8) {
                crc = crc shl 1
                if (crc and 0x1000000 != 0) crc = crc xor 0x864CFB
            }
        }
        return crc and 0xFFFFFF
    }

    /** The OpenPGP hash-algorithm id → the JCA MessageDigest name. */
    private fun hashName(hashAlg: Int): String = when (hashAlg) {
        HASH_SHA256 -> "SHA-256"
        else -> throw IllegalArgumentException("unsupported hash alg $hashAlg")
    }
}
