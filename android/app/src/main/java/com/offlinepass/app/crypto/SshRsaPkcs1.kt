package com.offlinepass.app.crypto

/**
 * RSA PKCS#1 v1.5 DigestInfo construction for OpenPGP-card signing: the
 * card's PSO:CDS performs RAW RSA over the transmitted block, so the
 * caller builds the standard `DigestInfo` (ASN.1 SEQUENCE of the hash
 * AlgorithmIdentifier and the digest) and pads it to the modulus size
 * (RFC 8017 §9.2). No crypto math here — the card does the RSA.
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
