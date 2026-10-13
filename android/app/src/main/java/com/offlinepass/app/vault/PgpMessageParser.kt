package com.offlinepass.app.vault

import java.io.ByteArrayOutputStream

/**
 * Minimal RFC 4880 (OpenPGP) message reader for the card-decrypt path:
 * locates the Public-Key Encrypted Session Key packets (PKESK) and the
 * Symmetrically Encrypted Integrity Protected Data packet (SEIPD) in a
 * `gpg --encrypt`-produced message.
 *
 * The card (via YubiKit) recovers the session key from the PKESK's
 * encrypted value; this parser hands over the pieces.
 */
object PgpMessageParser {

    data class Pkesk(
        val version: Int,
        val keyId: Long?,          // null for v6 (fingerprint-based)
        val keyFingerprint: ByteArray?,
        val keyAlgorithm: Int,
        /** The encrypted session-key value (the blob the card decrypts). */
        val encryptedSessionKey: ByteArray
    )

    data class Message(
        val pkesks: List<Pkesk>,
        /** SEIPD: symmetric algorithm octet + encrypted body (MDC included). */
        val seipdAlgo: Int?,
        val seipdBody: ByteArray?
    )

    fun parse(message: ByteArray): Message {
        var p = 0
        val pkesks = mutableListOf<Pkesk>()
        var seipdAlgo: Int? = null
        var seipdBody: ByteArray? = null

        fun readLen(b: ByteArray, pos: Int): Pair<Int, Int> {
            val first = b[pos].toInt() and 0xFF
            return if (first < 192) first to (pos + 1)
            else if (first >= 224 && first <= 254) ((first and 0x1F) shl 8 or (b[pos + 1].toInt() and 0xFF)) + 192 to (pos + 2)
            else if (first == 255) {
                var len = 0
                for (i in 1..4) len = (len shl 8) or (b[pos + i].toInt() and 0xFF)
                len to (pos + 5)
            } else throw UnsupportedOperationException("partial-length packets not supported")
        }

        while (p < message.size) {
            val tagByte = message[p].toInt() and 0xFF
            require(tagByte and 0x80 != 0) { "not an OpenPGP packet at offset $p" }
            val newFormat = (tagByte and 0x40) != 0
            val tag = if (newFormat) (tagByte and 0x3F) else ((tagByte shr 2) and 0x0F)
            p++
            var len: Int
            if (newFormat) {
                val r = readLen(message, p)
                len = r.first; p = r.second
            } else {
                when (tagByte and 0x03) {
                    0 -> { len = message[p].toInt() and 0xFF; p += 1 }
                    1 -> { len = ((message[p].toInt() and 0xFF) shl 8) or (message[p + 1].toInt() and 0xFF); p += 2 }
                    2 -> { len = 0; for (i in 0..3) len = (len shl 8) or (message[p + i].toInt() and 0xFF); p += 4 }
                    else -> throw UnsupportedOperationException("indeterminate length")
                }
            }
            val body = message.copyOfRange(p, p + len)
            p += len

            when (tag) {
                1 -> { // PKESK
                    val version = body[0].toInt() and 0xFF
                    if (version == 3) {
                        val keyId = body.copyOfRange(1, 9).let { bytesToLong(it) }
                        val algo = body[9].toInt() and 0xFF
                        // RSA (1..3, and legacy): one MPI. ECDH: OID len + point + two-octet length prefix.
                        val value = when (algo) {
                            in 1..3, 7, 8, 9 -> body.copyOfRange(10, body.size) // MPI incl. 2-byte length prefix
                            else -> body.copyOfRange(10, body.size)             // ECDH value (card handles the blob)
                        }
                        pkesks += Pkesk(version, keyId, null, algo, value)
                    } else {
                        // v6: fingerprint-based; parse minimally (v2 len + fp len + fp + algo + value)
                        val fpLen = body[1].toInt() and 0xFF
                        val fp = body.copyOfRange(2, 2 + fpLen)
                        val algo = body[2 + fpLen].toInt() and 0xFF
                        pkesks += Pkesk(version, null, fp, algo, body.copyOfRange(3 + fpLen, body.size))
                    }
                }
                18 -> { // SEIPD v1
                    require(body[0].toInt() == 1) { "only SEIPD v1 supported" }
                    seipdAlgo = body[1].toInt() and 0xFF
                    seipdBody = body.copyOfRange(2, body.size)
                }
                else -> { /* public keys, signatures, markers — skip */ }
            }
        }
        return Message(pkesks, seipdAlgo, seipdBody)
    }

    /** Decrypted PKESK value layout (v3/v4 session key): [0] = symmetric algo, then key, then 2-byte checksum. */
    fun sessionKeyFromPkeskValue(decrypted: ByteArray): Pair<Int, ByteArray> {
        val algo = decrypted[0].toInt() and 0xFF
        val key = decrypted.copyOfRange(1, decrypted.size - 2)
        // RFC 4880 checksum: sum of all plaintext bytes mod 65536.
        var sum = 0
        for (b in key) sum = (sum + (b.toInt() and 0xFF)) and 0xFFFF
        val check = ((decrypted[decrypted.size - 2].toInt() and 0xFF) shl 8) or
            (decrypted[decrypted.size - 1].toInt() and 0xFF)
        require(sum == check) { "session key checksum mismatch" }
        return algo to key
    }

    private fun bytesToLong(b: ByteArray): Long {
        var v = 0L
        for (x in b) v = (v shl 8) or (x.toLong() and 0xFF)
        return v
    }
}
