package com.offlinepass.app.crypto

/**
 * The PKCS#1 v1.5 type-2 strip: the raw card decrypt's output
 * (PSO:DEC's response) → the recovered session-data M value
 * (the algo || the session key || the checksum).
 *
 * The leading 00 may be present (the byte-preserving impls = the card
 * APDUs) or absent (the BigInteger-based impls strip it) — both handled.
 */
object OpenPgpSeipd {

    fun stripType2(block: ByteArray): ByteArray {
        val start = when {
            block.size > 1 && block[0] == 0x00.toByte() && block[1] == 0x02.toByte() -> 2
            block.isNotEmpty() && block[0] == 0x02.toByte() -> 1
            else -> throw IllegalArgumentException("not a type-2 block")
        }
        var sep = start
        while (sep < block.size && block[sep] != 0x00.toByte()) sep++
        require(sep > start && sep < block.size) { "no separator" }
        return block.copyOfRange(sep + 1, block.size)
    }
}
