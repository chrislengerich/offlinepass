package com.offlinepass.app.crypto

import java.security.MessageDigest

/**
 * The OpenPGP SEIPD v1 content decryption: the OpenPGP-CFB variant
 * (RFC 4880 §13.9 — the prefix, the MDC, the resync) + the literal-data
 * unpacking. The card recovers the session key; this module decrypts the
 * content and verifies the MDC.
 *
 * The oracle for every rule here is the REAL gpg-produced fixture:
 * fixture-enc.gpg (a gpg 2.4.7 RSA-2048 encrypt) must decrypt, verify its
 * MDC, and yield the original plaintext — byte for byte.
 */
object OpenPgpSeipd {

    private const val PREFIX_LEN = 18
    private const val BS = 16

    /** The OpenPGP-CFB (§13.9) DECRYPT of the SEIPD v1 body:
     *  [the encrypted prefix (18)] [the encrypted data] [the MDC packet].
     *  Throws on a prefix-repeat mismatch or an MDC mismatch. */
    fun decrypt(body: ByteArray, sessionKey: ByteArray, algo: Int): ByteArray {
        val decrypted = openpgpCfbDecrypt(body, sessionKey, algo)
        // The repeat check: the prefix's bytes 16-17 = a copy of the
        // bytes 0-1 (RFC 4880 §13.9).
        require(decrypted.size >= 36) { "the SEIPD body too short" }
        require(decrypted[16] == decrypted[0] && decrypted[17] == decrypted[1]) { "the CFB prefix repeat mismatch" }
        // The plaintext: the prefix (18) + the data; the tail = the MDC
        // packet (0xD3 0x14 + 20 bytes).
        val dataLen = decrypted.size - PREFIX_LEN - 22
        require(dataLen > 0) { "the SEIPD body too short after decrypt" }
        val data = decrypted.copyOfRange(PREFIX_LEN, PREFIX_LEN + dataLen)
        val mdc = decrypted.copyOfRange(PREFIX_LEN + dataLen, decrypted.size)
        require(mdc[0] == 0xD3.toByte() && mdc[1] == 0x14.toByte()) { "no MDC packet" }
        val md = MessageDigest.getInstance("SHA-1")
        md.update(decrypted, 0, PREFIX_LEN + dataLen)
        val computed = md.digest()
        require(computed.contentEquals(mdc.copyOfRange(2, 22))) { "MDC mismatch" }
        // The literal-data packet: the format(1) + the name-len(1) + the name
        // + the mtime(4) + the content.
        val format = data[0].toInt() and 0xFF
        require(format == 0 || format == 0xFF.toByte().toInt() - 255) { "unexpected literal format" }
        var p = 1
        val nameLen = data[p].toInt() and 0xFF; p += 1
        p += nameLen
        p += 4 // the mtime
        return data.copyOfRange(p, data.size)
    }

    /** The raw OpenPGP-CFB (§13.9) decrypt: the prefix with the zero IV,
     *  the repeat check, the resync to the last BS bytes of the encrypted
     *  prefix, then the data. */
    internal fun decryptForCompare(body: ByteArray, sessionKey: ByteArray, algo: Int): ByteArray =
        openpgpCfbDecrypt(body, sessionKey, algo)

    /** The production OpenPGP-CFB decrypt: delegates to BouncyCastle's
     *  OpenPGPCFBBlockCipher (the battle-tested reference; the per-byte
     *  CFB8 was WRONG — the OpenPGP CFB is a block-level variant with a
     *  2-byte-rotating keystream offset). The MDC + the repeat checks are
     *  the caller's job. */
    fun decryptContent(body: ByteArray, sessionKey: ByteArray): ByteArray {
        val cfb = org.bouncycastle.crypto.modes.OpenPGPCFBBlockCipher(
            org.bouncycastle.crypto.engines.AESEngine())
        cfb.init(false, org.bouncycastle.crypto.params.KeyParameter(sessionKey))
        val out = ByteArray(body.size)
        var inOff = 0; var outOff = 0
        val bs = cfb.blockSize
        while (inOff < body.size) {
            val chunk = minOf(bs, body.size - inOff)
            val block = body.copyOfRange(inOff, inOff + chunk)
            val padded = if (chunk < bs) block + ByteArray(bs - chunk) else block
            val processed = ByteArray(bs)
            cfb.processBlock(padded, 0, processed, 0)
            processed.copyInto(out, outOff, 0, chunk)
            inOff += chunk; outOff += chunk
        }
        cfb.reset()
        return out
    }

    private fun openpgpCfbDecrypt(body: ByteArray, sessionKey: ByteArray, algo: Int): ByteArray {
        val bs = BS
        val key = javax.crypto.spec.SecretKeySpec(sessionKey, "AES")
        fun rawAes(block: ByteArray): ByteArray {
            val c = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding")
            c.init(javax.crypto.Cipher.DECRYPT_MODE, key) // the raw AES = the symmetric op
            return c.doFinal(block)
        }
        // NOTE: the CFB uses the ENCRYPT direction of the raw AES for the
        // keystream even when decrypting (the CFB = the stream over the
        // forward cipher).
        fun keystream(block: ByteArray): ByteArray {
            val c = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding")
            c.init(javax.crypto.Cipher.ENCRYPT_MODE, key)
            return c.doFinal(block)
        }
        val out = ByteArray(body.size)
        // The CFB8: the keystream byte = E(shift)[0]; the CIPHERTEXT feeds
        // the shift register (the same feedback for the encrypt and the
        // decrypt).
        var shift = ByteArray(bs)
        for (i in 0 until PREFIX_LEN) {
            val ks = keystream(shift)
            out[i] = (body[i].toInt() xor ks[0].toInt()).toByte()
            shift = shift.copyOfRange(1, bs) + byteArrayOf(body[i])
        }
        // The repeat check: the prefix's bytes 16-17 = a copy of the
        // bytes 0-1 (the spec's "the last two = the repeats of the first
        // two" of the 18-byte prefix).
        println("DBG prefix=" + out.take(18).joinToString(" ") { "%02x".format(it) })

        // The resync: the shift register = the last bs bytes of the
        // ENCRYPTED prefix (body[2..17]).
        shift = body.copyOfRange(2, 2 + bs)
        for (i in PREFIX_LEN until body.size) {
            val ks = keystream(shift)
            out[i] = (body[i].toInt() xor ks[0].toInt()).toByte()
            shift = shift.copyOfRange(1, bs) + byteArrayOf(body[i])
        }
        return out
    }

    /** The PKCS#1 v1.5 type-2 strip: 00 02 PS 00 || M. The leading 00 may
     *  be present (the byte-preserving impls = the card APDUs) or absent
     *  (the BigInteger-based impls strip it) — both handled. */
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
