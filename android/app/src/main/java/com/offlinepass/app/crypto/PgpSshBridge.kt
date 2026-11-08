package com.offlinepass.app.crypto

import java.math.BigInteger
import java.util.Base64

/**
 * Bridges OpenPGP detached signatures to SSH auth signatures.
 *
 * A YubiKey's OpenPGP AUTH subkey is already enrolled in GitHub as an SSH
 * key (desktop gpg-agent pushes use it). SSH userauth requires a RAW
 * signature over the exchange blob, while OpenKeyChain's remote API
 * returns an OpenPGP detached signature (framed packet). This bridge
 * parses the OpenPGP v4 signature packet and extracts the raw signature
 * values, mapped to the SSH algorithm name:
 *
 *   RSA      (alg 1)  → one MPI → pad to modulus size → rsa-sha2-256/512
 *                       (by PGP hash algo: 8=SHA-256, 10=SHA-512)
 *   ECDSA    (alg 19) → two MPIs (r, s) → 0x04||r||s point form
 *                       → ecdsa-sha2-nistp256
 *   EdDSA    (alg 22) → two MPIs (r, s) → ssh-ed25519
 *
 * The wire format follows RFC 4253/5656: string(algorithm) + string(sig).
 */
object PgpSshBridge {

    class PgpSshBridgeException(message: String) : Exception(message)

    // PGP pubkey algorithms
    private const val PK_ALG_RSA = 1
    private const val PK_ALG_ECDSA = 19
    private const val PK_ALG_EDDSA = 22
    // PGP hash algorithms
    private const val HASH_SHA256 = 8
    private const val HASH_SHA512 = 10

    /** The OpenSSH public-key line the user enrolled in GitHub, split. */
    data class SshPublicKeyLine(
        val algorithm: String,   // "ssh-rsa" | "ecdsa-sha2-nistp256" | "ssh-ed25519"
        val wireBlob: ByteArray, // the base64 blob, decoded
        val comment: String
    )

    fun parsePublicKeyLine(line: String): SshPublicKeyLine {
        val parts = line.trim().split(" ").filter { it.isNotBlank() }
        if (parts.size < 2) throw PgpSshBridgeException("SSH public key line needs at least: <alg> <b64blob>")
        val blob = runCatching { Base64.getDecoder().decode(parts[1]) }
            .getOrElse { throw PgpSshBridgeException("public key blob is not valid base64") }
        return SshPublicKeyLine(parts[0], blob, parts.drop(2).joinToString(" "))
    }

    /** Modulus byte-size for ssh-rsa blobs (for RSA signature padding). */
    fun rsaModulusSize(blob: ByteArray): Int {
        var p = readU32String(blob, 0).second          // skip algorithm string
        p = readU32String(blob, p).second             // skip e
        val (n, _) = readU32String(blob, p)           // n
        return n.size
    }

    /**
     * Converts an OpenPGP detached signature (armored) into the SSH
     * signature blob for the given public-key line:
     * string(signatureAlgorithm) + string(signature bytes).
     */
    fun openPgpToSshSignature(armored: String, publicKeyLine: SshPublicKeyLine): ByteArray {
        val (pubkeyAlg, hashAlg, mpis) = parsePgpSignature(armored)
        val raw = rawSignatureBytes(pubkeyAlg, hashAlg, mpis, publicKeyLine)
        val sigName = signatureAlgorithmName(publicKeyLine.algorithm, pubkeyAlg, hashAlg)
        return sshString(sigName.toByteArray()) + sshString(raw)
    }

    /** The RAW signature bytes (no SSH framing) for the given OpenSSH
     *  algorithm — RSA padded to modulus size, ECDSA as 0x04||r||s,
     *  Ed25519 as r||s. */
    fun extractRawSignature(armored: String, sshAlgorithm: String): ByteArray {
        val (pubkeyAlg, hashAlg, mpis) = parsePgpSignature(armored)
        return rawSignatureBytes(pubkeyAlg, hashAlg, mpis,
            SshPublicKeyLine(sshAlgorithm, ByteArray(0), ""))
    }

    private data class PgpSig(val pubkeyAlg: Int, val hashAlg: Int, val mpis: List<ByteArray>)

    private fun parsePgpSignature(armored: String): PgpSig {
        val packet = dearmorFirstSignaturePacket(armored)
        val body = parsePacketBody(packet)
        val version = body[0].toInt() and 0xFF
        if (version != 4) throw PgpSshBridgeException("unsupported OpenPGP signature version $version")
        val pubkeyAlg = body[2].toInt() and 0xFF
        val hashAlg = body[3].toInt() and 0xFF
        var p = 4
        p += 2 + u16(body, p)             // hashed subpacket length + data
        p += 2 + u16(body, p)             // unhashed subpacket length + data
        val mpis = mutableListOf<ByteArray>()
        when (pubkeyAlg) {
            PK_ALG_RSA -> mpis += readMpi(body, p).first
            PK_ALG_ECDSA, PK_ALG_EDDSA -> {
                val (r, p2) = readMpi(body, p)
                val (s, _) = readMpi(body, p2)
                mpis += r; mpis += s
            }
            else -> throw PgpSshBridgeException("unsupported OpenPGP pubkey algorithm $pubkeyAlg")
        }
        return PgpSig(pubkeyAlg, hashAlg, mpis)
    }

    private fun signatureAlgorithmName(sshAlgorithm: String, pubkeyAlg: Int, hashAlg: Int): String {
        if (sshAlgorithm == "ssh-rsa") {
            if (pubkeyAlg != PK_ALG_RSA)
                throw PgpSshBridgeException("signature algorithm mismatch: expected RSA, got $pubkeyAlg")
            return when (hashAlg) {
                HASH_SHA256 -> "rsa-sha2-256"
                HASH_SHA512 -> "rsa-sha2-512"
                else -> throw PgpSshBridgeException("unsupported PGP hash algorithm $hashAlg (need SHA-256/512)")
            }
        }
        return sshAlgorithm
    }

    private fun rawSignatureBytes(
        pubkeyAlg: Int,
        hashAlg: Int,
        mpis: List<ByteArray>,
        line: SshPublicKeyLine
    ): ByteArray = when (line.algorithm) {
        "ssh-rsa" -> {
            if (pubkeyAlg != PK_ALG_RSA)
                throw PgpSshBridgeException("signature algorithm mismatch: expected RSA, got $pubkeyAlg")
            padLeft(mpis[0], rsaModulusSize(line.wireBlob))
        }
        "ecdsa-sha2-nistp256" -> {
            if (pubkeyAlg != PK_ALG_ECDSA)
                throw PgpSshBridgeException("signature algorithm mismatch: expected ECDSA, got $pubkeyAlg")
            if (hashAlg != HASH_SHA256)
                throw PgpSshBridgeException("nistp256 needs SHA-256 signatures, got hash $hashAlg")
            byteArrayOf(0x04) + padLeft(mpis[0], 32) + padLeft(mpis[1], 32)
        }
        "ssh-ed25519" -> {
            if (pubkeyAlg != PK_ALG_EDDSA)
                throw PgpSshBridgeException("signature algorithm mismatch: expected EdDSA, got $pubkeyAlg")
            padLeft(mpis[0], 32) + padLeft(mpis[1], 32)
        }
        else -> throw PgpSshBridgeException("unsupported SSH algorithm ${line.algorithm}")
    }

    // -- packet-level helpers -------------------------------------------------

    /** De-arms an ASCII-detached signature and returns the FIRST packet's
     *  raw bytes (tag + length + body). */
    private fun dearmorFirstSignaturePacket(armored: String): ByteArray {
        val b64 = armored.lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("-") && !it.contains(":") }
            .joinToString("")
        val data = runCatching { Base64.getDecoder().decode(b64) }
            .getOrElse { throw PgpSshBridgeException("signature armor is not valid base64") }
        if (data.isEmpty()) throw PgpSshBridgeException("empty signature packet")
        val b0 = data[0].toInt() and 0xFF
        val tagOk = (b0 and 0xC0) == 0xC0 && (b0 and 0x3F) == 2
        if (!tagOk) throw PgpSshBridgeException("first packet is not an OpenPGP signature packet (byte $b0)")
        // New-format length: 1/2/5 octets
        val lenByte = data[1].toInt() and 0xFF
        val (len, hdrLen) = when {
            lenByte < 192 -> lenByte to 2
            lenByte in 192..223 -> (((lenByte - 192) shl 8) or (data[2].toInt() and 0xFF)) + 192 to 3
            lenByte == 255 -> {
                val l = ((data[2].toInt() and 0xFF) shl 24) or ((data[3].toInt() and 0xFF) shl 16) or
                    ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
                l to 6
            }
            else -> throw PgpSshBridgeException("malformed packet length")
        }
        if (data.size < hdrLen + len) throw PgpSshBridgeException("truncated signature packet")
        return data  // full packet: tag + length-encoding + body (parsed next)
    }

    /** Strips the packet header (tag + length), returning the body. */
    private fun parsePacketBody(packet: ByteArray): ByteArray {
        val lenByte = packet[1].toInt() and 0xFF
        val hdrLen = when {
            lenByte < 192 -> 2
            lenByte in 192..223 -> 3
            lenByte == 255 -> 6
            else -> throw PgpSshBridgeException("malformed packet length")
        }
        return packet.copyOfRange(hdrLen, packet.size)
    }

    private fun u16(b: ByteArray, p: Int): Int = ((b[p].toInt() and 0xFF) shl 8) or (b[p + 1].toInt() and 0xFF)

    /** OpenPGP MPI: 2-byte BIT LENGTH + big-endian value. Returns (bytes, nextPos). */
    private fun readMpi(b: ByteArray, p: Int): Pair<ByteArray, Int> {
        if (p + 2 > b.size) throw PgpSshBridgeException("truncated MPI")
        val bits = u16(b, p)
        val len = (bits + 7) / 8
        if (p + 2 + len > b.size) throw PgpSshBridgeException("truncated MPI body")
        return b.copyOfRange(p + 2, p + 2 + len) to (p + 2 + len)
    }

    /** SSH wire string: 4-byte big-endian length + bytes. Returns (bytes, nextPos). */
    private fun readU32String(b: ByteArray, p: Int): Pair<ByteArray, Int> {
        if (p + 4 > b.size) throw PgpSshBridgeException("truncated string")
        val len = ((b[p].toInt() and 0xFF) shl 24) or ((b[p + 1].toInt() and 0xFF) shl 16) or
            ((b[p + 2].toInt() and 0xFF) shl 8) or (b[p + 3].toInt() and 0xFF)
        if (p + 4 + len > b.size) throw PgpSshBridgeException("truncated string body")
        return b.copyOfRange(p + 4, p + 4 + len) to (p + 4 + len)
    }

    private fun padLeft(v: ByteArray, size: Int): ByteArray {
        if (v.size >= size) {
            // An MPI may carry one extra leading zero; strip it back down.
            return if (v.size == size) v else v.copyOfRange(v.size - size, v.size)
        }
        return ByteArray(size - v.size) + v
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
}
