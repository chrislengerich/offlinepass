package com.offlinepass.app.crypto

/**
 * RSA PKCS#1 v1.5 building blocks for OpenPGP-card signing.
 *
 * The OpenPGP card's PSO:CDS does the PKCS#1 v1.5 PADDING ON CARD (Java
 * Card's ALG_RSA_PKCS1 expects the bare `DigestInfo` — sending a
 * pre-padded block exceeds modLen-11 and the card fails with 0x6581).
 * So the card receives [digestInfo] and returns the padded-block RSA
 * signature — exactly what the SSH wire wants raw.
 *
 * [pkcs1SignBlock] builds the full RFC 8017 §9.2 block client-side for
 * verification against JCA and for software-key paths.
 */
object SshRsaPkcs1 {

    // The DigestInfo prefixes for the supported hashes (RFC 8017 §9.2 fn. 1).
    private val SHA1_PREFIX = byteArrayOf(
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
        0x05, 0x00, 0x04, 0x14.toByte())
    private val SHA256_PREFIX = byteArrayOf(
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01, 0x65,
        0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20)
    private val SHA512_PREFIX = byteArrayOf(
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01, 0x65,
        0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40.toByte())

    /** The bare `DigestInfo` (ASN.1 SEQUENCE of the hash
     *  AlgorithmIdentifier and the digest) — the input the OpenPGP card's
     *  PSO:CDS expects; the card pads it to the modulus size. */
    fun digestInfo(hashAlg: String, message: ByteArray): ByteArray {
        val prefix = prefixFor(hashAlg)
        return prefix + java.security.MessageDigest.getInstance(hashAlg).digest(message)
    }

    /** The PKCS#1 v1.5 encoded block: 0x00 0x01 PS 0x00 DigestInfo, where PS
     *  is 0xFF-filled to make the block exactly [modulusSize] bytes (the
     *  encoding length ≥ 8 octets of padding is guaranteed for any real
     *  modulus). */
    fun pkcs1SignBlock(hashAlg: String, message: ByteArray, modulusSize: Int): ByteArray {
        val prefix = prefixFor(hashAlg)
        val digest = java.security.MessageDigest.getInstance(hashAlg).digest(message)
        val digestInfo = prefix + digest
        val padLen = modulusSize - digestInfo.size - 3
        require(padLen >= 8) {
            "modulus too small for a $hashAlg PKCS#1 block (needs ${digestInfo.size + 11} bytes)"
        }
        return byteArrayOf(0x00, 0x01) + ByteArray(padLen) { 0xFF.toByte() } +
            byteArrayOf(0x00) + digestInfo
    }

    private fun prefixFor(hashAlg: String): ByteArray = when (hashAlg) {
        "rsa-sha2-512", "SHA-512" -> SHA512_PREFIX
        "rsa-sha2-256", "SHA-256" -> SHA256_PREFIX
        "ssh-rsa", "SHA-1" -> SHA1_PREFIX
        else -> throw IllegalArgumentException("unsupported hash: $hashAlg")
    }
}
