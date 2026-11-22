package com.offlinepass.app.vault

import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** RFC 6238 TOTP, ported from the desktop `passlib` implementation. */
object Totp {
    private fun base32Decode(secret: String): ByteArray {
        val clean = secret.replace(" ", "").replace("-", "").uppercase()
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var bits = 0
        var value = 0
        val out = ArrayList<Byte>()
        for (c in clean) {
            val idx = alphabet.indexOf(c)
            if (idx < 0) continue
            value = (value shl 5) or idx
            bits += 5
            if (bits >= 8) {
                out.add(((value shr (bits - 8)) and 0xFF).toByte())
                bits -= 8
            }
        }
        return out.toByteArray()
    }

    fun parseOtpauth(uri: String): Quad {
        require(uri.startsWith("otpauth://")) { "Not an otpauth URI: $uri" }
        val query = uri.substringAfter('?')
        val params = query.split('&').mapNotNull {
            val i = it.indexOf('=')
            if (i <= 0) null else it.substring(0, i) to java.net.URLDecoder.decode(it.substring(i + 1), "UTF-8")
        }.toMap()
        val secret = params["secret"] ?: throw IllegalArgumentException("No secret in TOTP URI")
        return Quad(
            secret = secret,
            issuer = params["issuer"] ?: "",
            digits = params["digits"]?.toInt() ?: 6,
            period = params["period"]?.toInt() ?: 30
        )
    }

    data class Quad(val secret: String, val issuer: String, val digits: Int, val period: Int)

    /** Accepts a raw base32 secret or an otpauth:// URI; returns a normalized otpauth:// URI. */
    fun normalizeSecretInput(input: String): String {
        val trimmed = input.trim()
        if (trimmed.startsWith("otpauth://")) return trimmed
        val clean = trimmed.replace(" ", "").replace("-", "").uppercase()
        return "otpauth://totp/offlinepass?secret=$clean&issuer=offlinepass"
    }

    /** Returns (code, seconds remaining in period). */
    fun generate(uri: String, atTime: Long = System.currentTimeMillis() / 1000): Pair<String, Int> {
        val q = parseOtpauth(uri)
        val key = base32Decode(q.secret)
        val counter = atTime / q.period
        val remaining = (q.period - (atTime % q.period)).toInt()
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "HmacSHA1"))
        val msg = ByteArray(8)
        var c = counter
        for (i in 7 downTo 0) {
            msg[i] = (c and 0xFF).toByte()
            c = c shr 8
        }
        val h = mac.doFinal(msg)
        val offset = (h[h.size - 1].toInt() and 0x0F)
        val codeInt = ((h[offset].toInt() and 0x7F) shl 24) or
            ((h[offset + 1].toInt() and 0xFF) shl 16) or
            ((h[offset + 2].toInt() and 0xFF) shl 8) or
            (h[offset + 3].toInt() and 0xFF)
        val code = (codeInt.toString()).padStart(q.digits, '0').takeLast(q.digits)
        return code to remaining
    }
}

/** Password/alias generation, ported from the desktop `passlib`.
 *  The default = ALPHANUMERIC 10-char (the user's preference: the
 *  shorter, the symbols-free — the digits and the cases carry the
 *  strength; the symbols' shell/quoting friction avoided). */
object PasswordGen {
    private const val ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    fun password(length: Int = 16): String {
        val rnd = java.security.SecureRandom()
        return buildString { repeat(length) { append(ALPHANUMERIC[rnd.nextInt(ALPHANUMERIC.length)]) } }
    }

    /** SimpleLogin-style alias stub (not registered anywhere). */
    fun alias(): String {
        val adjectives = listOf("quick", "lazy", "happy", "silent", "bright", "calm", "eager")
        val nouns = listOf("fox", "river", "stone", "leaf", "wind", "star", "wave")
        val rnd = java.security.SecureRandom()
        return "${adjectives[rnd.nextInt(adjectives.size)]}.${nouns[rnd.nextInt(nouns.size)]}${rnd.nextInt(1000)}@aleeas.com"
    }

    fun deviceId(): String = UUID.randomUUID().toString()
}
