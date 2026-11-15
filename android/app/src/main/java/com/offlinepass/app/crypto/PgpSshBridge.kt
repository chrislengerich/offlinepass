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

    /** ssh-keygen-style fingerprint ("SHA256:<unpadded b64>") of the blob
     *  inside an OpenSSH public-key line. */
    fun fingerprintOf(publicKeyLine: String): String {
        val parsed = parsePublicKeyLine(publicKeyLine)
        return "SHA256:" + java.util.Base64.getEncoder().withoutPadding()
            .encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(parsed.wireBlob))
    }

    fun parsePublicKeyLine(line: String): SshPublicKeyLine {
        val parts = line.trim().split(" ").filter { it.isNotBlank() }
        if (parts.size < 2) throw PgpSshBridgeException("SSH public key line needs at least: <alg> <b64blob>")
        val blob = runCatching { Base64.getDecoder().decode(parts[1]) }
            .getOrElse { throw PgpSshBridgeException("public key blob is not valid base64") }
        return SshPublicKeyLine(parts[0], blob, parts.drop(2).joinToString(" "))
    }

    /** The de-armored SIGNATURE packet's body (for the self-test's
     *  diagnostics). */
    fun sigBodyOf(armored: String): ByteArray =
        parsePacketBody(dearmorFirstSignaturePacket(armored))

    /** For an ssh-ed25519 line: the 32-byte Ed25519 public point (the blob
     *  is string("ssh-ed25519") + string(32B point)). */
    fun authKeyPoint(line: SshPublicKeyLine): ByteArray {
        if (line.algorithm != "ssh-ed25519")
            throw PgpSshBridgeException("authKeyPoint: not an ssh-ed25519 line")
        if (line.wireBlob.size < 36)
            throw PgpSshBridgeException("ssh-ed25519 blob too short")
        return line.wireBlob.copyOfRange(line.wireBlob.size - 32, line.wireBlob.size)
    }

    /** The KEY id of a key material's PRIMARY (first tag-6) packet — for
     *  the sign-request diagnostics. */
    fun primaryKeyIdOf(armoredKeyring: String): Long? {
        val data = dearmor(armoredKeyring)
        for ((tag, body) in packets(data)) {
            if (tag == 6 && body.isNotEmpty() && (body[0].toInt() and 0xFF) == 4) {
                val fpInput = byteArrayOf(0x99.toByte()) +
                    byteArrayOf(((body.size ushr 8) and 0xFF).toByte(), (body.size and 0xFF).toByte()) + body
                val sha1 = java.security.MessageDigest.getInstance("SHA-1").digest(fpInput)
                return (0 until 8).fold(0L) { acc, k ->
                    (acc shl 8) or (sha1[sha1.size - 8 + k].toLong() and 0xFF)
                }
            }
        }
        return null
    }

    /** Modulus byte-size for ssh-rsa blobs (for RSA signature padding). */
    // -- OpenPGP key material → SSH public line -------------------------------

    /** Builds the OpenSSH public-key line for [keyId] from an ARMORED
     *  OpenPGP key (the keyring OpenKeyChain's API returns): walks the
     *  packets, finds the public key/subkey whose v4 fingerprint's last
     *  8 bytes equal [keyId], and converts its key material to the SSH
     *  wire blob. Supports RSA (ssh-rsa), ECDSA nistp256, Ed25519. */
    fun sshLineForKeyMaterial(armoredKeyring: String, keyId: Long, comment: String): String {
        val data = dearmor(armoredKeyring)
        for ((tag, body) in packets(data)) {
            if ((tag == 6 || tag == 14) && body.isNotEmpty() && (body[0].toInt() and 0xFF) == 4) {
                // v4 public key/subkey: version(1) + creation(4) + alg(1) + MPIs
                val alg = body[5].toInt() and 0xFF
                // v4 fingerprint: SHA-1 over 0x99 || u16(len) || body
                val fpInput = byteArrayOf(0x99.toByte()) +
                    byteArrayOf(((body.size ushr 8) and 0xFF).toByte(), (body.size and 0xFF).toByte()) + body
                val sha1 = java.security.MessageDigest.getInstance("SHA-1").digest(fpInput)
                val pktId = (0 until 8).fold(0L) { acc, k ->
                    (acc shl 8) or (sha1[sha1.size - 8 + k].toLong() and 0xFF)
                }
                if (pktId == keyId) {
                    // Parse the alg-specific MPIs starting after creation time.
                    val mpis = parsePubkeyMpis(alg, body.copyOfRange(6, body.size))
                    val (sshAlg, blob) = sshBlobFor(alg, mpis)
                    return "$sshAlg ${java.util.Base64.getEncoder().encodeToString(blob)} $comment"
                }
            }
        }
        throw PgpSshBridgeException("key ${"%016X".format(keyId)} not found in the key material")
    }

    /**
     * Resolves the SUBKEY that can actually sign, from an OpenPGP key's
     * material: OpenKeyChain's key picker can hand back the key's PRIMARY
     * id even when the signing secret lives in a dedicated subkey — and
     * detached-signing with a non-signing id fails silently (no touch, no
     * prompt: OKK rejects the request before any card operation).
     *
     * Walks the key's self-signatures reading the KEY FLAGS subpacket
     * (type 27; bit 0x02 = sign) and returns:
     *  - [preferredKeyId] when that key/subkey carries the sign flag,
     *  - else the FIRST sign-capable subkey id,
     *  - else null (nothing can sign).
     * RFC 4880: an absent KEY FLAGS subpacket means "all capabilities" —
     * treated as sign-capable.
     */
    fun signingSubkeyKeyId(armoredKeyring: String, preferredKeyId: Long?): Long? {
        val data = dearmor(armoredKeyring)
        val grantsSign = linkedMapOf<Long, Boolean>()
        val sawFlags = linkedMapOf<Long, Boolean>()
        val isSubkey = linkedMapOf<Long, Boolean>()
        var currentKeyId: Long? = null
        for ((tag, body) in packets(data)) {
            when (tag) {
                6, 14 -> if (body.isNotEmpty() && (body[0].toInt() and 0xFF) == 4) {
                    val fpInput = byteArrayOf(0x99.toByte()) +
                        byteArrayOf(((body.size ushr 8) and 0xFF).toByte(), (body.size and 0xFF).toByte()) + body
                    val sha1 = java.security.MessageDigest.getInstance("SHA-1").digest(fpInput)
                    val pktId = (0 until 8).fold(0L) { acc, k ->
                        (acc shl 8) or (sha1[sha1.size - 8 + k].toLong() and 0xFF)
                    }
                    currentKeyId = pktId
                    grantsSign.putIfAbsent(pktId, false)
                    sawFlags.putIfAbsent(pktId, false)
                    isSubkey.putIfAbsent(pktId, tag == 14)
                }
                2 -> if (currentKeyId != null) {
                    val flags = keyFlagsInSignature(body) ?: continue
                    sawFlags[currentKeyId] = true
                    if (flags and 0x02 != 0) grantsSign[currentKeyId] = true
                }
            }
        }
        // A key only counts when it exists in the material; capable = granted
        // by a self-sig, or no flags information at all (RFC 4880 default).
        fun capable(id: Long): Boolean =
            grantsSign.containsKey(id) &&
                (grantsSign[id] == true || sawFlags[id] != true)
        if (preferredKeyId != null && capable(preferredKeyId)) return preferredKeyId
        // Prefer a sign-capable SUBKEY; a capable primary is the fallback.
        return grantsSign.keys.firstOrNull { capable(it) && isSubkey[it] == true }
            ?: grantsSign.keys.firstOrNull { capable(it) }
    }

    /** The KEY FLAGS bits of a signature's HASHED subpacket area (null when
     *  the signature carries no flags — "all capabilities" per RFC 4880). */
    private fun keyFlagsInSignature(sigBody: ByteArray): Int? {
        if (sigBody.isEmpty() || (sigBody[0].toInt() and 0xFF) != 4) return null
        var p = 4
        val hashedLen = u16(sigBody, p)
        val hashedEnd = p + 2 + hashedLen
        p += 2
        while (p + 2 <= hashedEnd && p + 2 <= sigBody.size) {
            val b0 = sigBody[p].toInt() and 0xFF
            val len: Int
            val hdrLen: Int
            when {
                b0 < 192 -> { len = b0; hdrLen = 1 }
                b0 < 255 -> { len = ((b0 - 192) shl 8) or (sigBody[p + 1].toInt() and 0xFF); hdrLen = 2 }
                else -> { len = ((sigBody[p + 1].toInt() and 0xFF) shl 24) or
                    ((sigBody[p + 2].toInt() and 0xFF) shl 16) or
                    ((sigBody[p + 3].toInt() and 0xFF) shl 8) or
                    (sigBody[p + 4].toInt() and 0xFF); hdrLen = 5 }
            }
            val type = sigBody[p + hdrLen].toInt() and 0xFF
            if (type == 27) { // KEY FLAGS: the first octet's bit 0x02 = sign
                val flags = sigBody[p + hdrLen + 1].toInt() and 0xFF
                return flags
            }
            p += hdrLen + len
        }
        return null
    }

    /** Generic OpenPGP packet walk over binary keyring data: (tag, body). */
    private fun packets(data: ByteArray): List<Pair<Int, ByteArray>> {
        val out = mutableListOf<Pair<Int, ByteArray>>()
        var p = 0
        while (p < data.size) {
            val b0 = data[p].toInt() and 0xFF
            if ((b0 and 0x80) == 0) throw PgpSshBridgeException("bad packet tag at $p")
            val tag: Int
            var bodyStart: Int
            var bodyLen: Int
            if ((b0 and 0x40) != 0) { // new format
                tag = b0 and 0x3F
                val lb = data[p + 1].toInt() and 0xFF
                when {
                    lb < 192 -> { bodyLen = lb; bodyStart = p + 2 }
                    lb in 192..223 -> {
                        bodyLen = (((lb - 192) shl 8) or (data[p + 2].toInt() and 0xFF)) + 192
                        bodyStart = p + 3
                    }
                    lb == 255 -> {
                        bodyLen = 0; for (k in 1..4) bodyLen = (bodyLen shl 8) or (data[p + 1 + k].toInt() and 0xFF)
                        bodyStart = p + 6
                    }
                    else -> throw PgpSshBridgeException("bad new-format length at $p")
                }
            } else { // old format
                tag = (b0 shr 2) and 0x0F
                val lt = b0 and 0x03
                // The header is tag(1) + the length octets — the body starts
                // right after (the +1 is the tag byte; +2 would skip a byte
                // of key material and shift every fingerprint).
                val lenSize = when (lt) { 0 -> 1; 1 -> 2; 2 -> 4; else -> throw PgpSshBridgeException("bad old-format length at $p") }
                bodyLen = when (lt) {
                    0 -> data[p + 1].toInt() and 0xFF
                    1 -> ((data[p + 1].toInt() and 0xFF) shl 8) or (data[p + 2].toInt() and 0xFF)
                    2 -> { var l = 0; for (k in 1..4) l = (l shl 8) or (data[p + 1 + k].toInt() and 0xFF); l }
                    else -> throw PgpSshBridgeException("bad old-format length at $p")
                }
                bodyStart = p + 1 + lenSize
            }
            out += tag to data.copyOfRange(bodyStart, bodyStart + bodyLen)
            p = bodyStart + bodyLen
        }
        return out
    }

    /** The alg-specific MPIs of a v4 public key/subkey body (after the
     *  version + creation-time bytes). */
    private fun parsePubkeyMpis(alg: Int, keyBody: ByteArray): List<ByteArray> {
        var p = 0
        val out = mutableListOf<ByteArray>()
        when (alg) {
            PK_ALG_RSA -> {
                val (n, p2) = readMpi(keyBody, p); p = p2
                val (e, _) = readMpi(keyBody, p)
                out += n; out += e   // OpenPGP order: n, e
            }
            PK_ALG_ECDSA, PK_ALG_EDDSA -> {
                // RFC 6637: the named-curve OID (1-octet length + bytes), then the point MPI.
                val olen = keyBody[p].toInt() and 0xFF
                val oid = keyBody.copyOfRange(p + 1, p + 1 + olen); p += 1 + olen
                val (q, _) = readMpi(keyBody, p)
                out += oid; out += q
            }
            else -> throw PgpSshBridgeException("unsupported pubkey algorithm $alg")
        }
        return out
    }

    /** The SSH wire blob from the OpenPGP key material. */
    private fun sshBlobFor(alg: Int, mpis: List<ByteArray>): Pair<String, ByteArray> = when (alg) {
        PK_ALG_RSA -> "ssh-rsa" to (sshString("ssh-rsa".toByteArray()) + sshString(mpis[1]) + sshString(mpis[0]))
        PK_ALG_ECDSA -> {
            val curve = curveNameForOid(mpis[0])
            val q = mpis[1]
            val name = "ecdsa-sha2-" + curve
            name to (sshString(name.toByteArray()) + sshString(curve.toByteArray()) + sshString(q))
        }
        PK_ALG_EDDSA -> {
            // The OpenPGP point MPI: 0x04||x||y → the SSH key data is the raw x||y.
            val q = mpis[1]
            val raw32 = q.copyOfRange(1, q.size)  // strip the 0x04 prefix (uncompressed point)
            "ssh-ed25519" to (sshString("ssh-ed25519".toByteArray()) + sshString(raw32))
        }
        else -> throw PgpSshBridgeException("unsupported pubkey algorithm $alg")
    }

    private fun curveNameForOid(oid: ByteArray): String = when {
        oid.contentEquals(byteArrayOf(0x2A.toByte(), 0x86.toByte(), 0x48.toByte(), 0xCE.toByte(), 0x3D.toByte(), 0x03.toByte(), 0x01.toByte(), 0x07.toByte())) -> "nistp256"
        oid.contentEquals(byteArrayOf(0x2B.toByte(), 0x81.toByte(), 0x04.toByte(), 0x00.toByte(), 0x22.toByte())) -> "nistp384"
        oid.contentEquals(byteArrayOf(0x2B.toByte(), 0x81.toByte(), 0x04.toByte(), 0x00.toByte(), 0x23.toByte())) -> "nistp521"
        else -> throw PgpSshBridgeException("unsupported curve OID")
    }

    /** Generic dearmor: strips the ASCII armor headers/footers, decodes
     *  the base64 body. */
    private fun dearmor(armored: String): ByteArray {
        val b64 = armored.lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("-") && !it.contains(":") &&
                // The armor CRC24 checksum ("=XXXX") is not part of the
                // base64 body.
                !it.startsWith("=") }
            .joinToString("")
        return runCatching { Base64.getDecoder().decode(b64) }
            .getOrElse { throw PgpSshBridgeException("armor is not valid base64") }
    }

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

    data class RawSig(val bytes: ByteArray, val hashAlg: Int)

    /** The RAW signature bytes (no SSH framing) for the given OpenSSH
     *  algorithm — RSA padded to modulus size, ECDSA as 0x04||r||s,
     *  Ed25519 as r||s — plus the PGP hash algorithm used. The LINE variant
     *  carries the modulus size (RSA signatures must be padded to it). */
    fun extractRawSignature(armored: String, sshAlgorithm: String): RawSig =
        extractRawSignature(armored, SshPublicKeyLine(sshAlgorithm, ByteArray(0), ""))

    fun extractRawSignature(armored: String, line: SshPublicKeyLine): RawSig {
        val (pubkeyAlg, hashAlg, mpis) = parsePgpSignature(armored)
        return RawSig(rawSignatureBytes(pubkeyAlg, hashAlg, mpis, line), hashAlg)
    }

    /** The SSH signature-algorithm name matching a PGP hash for an
     *  ssh-rsa key: SHA-256 → rsa-sha2-256, SHA-512 → rsa-sha2-512. */
    fun rsaSigNameForHash(hashAlg: Int): String = when (hashAlg) {
        HASH_SHA256 -> "rsa-sha2-256"
        HASH_SHA512 -> "rsa-sha2-512"
        else -> throw PgpSshBridgeException("unsupported PGP hash algorithm $hashAlg (need SHA-256/512)")
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

    /** De-arms an ASCII-detached signature and returns the packet bytes
     *  (tag + length + body). Strips the headers, the CRC24 ("=XXXX") line
     *  and empties — a strict base64 decoder rejects the CRC line
     *  mid-stream. Accepts OLD- and NEW-format packet headers (gpg/OKK
     *  emit old-format: 0x88..). */
    private fun dearmorFirstSignaturePacket(armored: String): ByteArray {
        val b64 = armored.lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("-") && !it.contains(":") && !it.startsWith("=") }
            .joinToString("")
        val data = runCatching { Base64.getDecoder().decode(b64) }
            .getOrElse { throw PgpSshBridgeException("signature armor is not valid base64") }
        if (data.isEmpty()) throw PgpSshBridgeException("empty signature packet")
        val b0 = data[0].toInt() and 0xFF
        if ((b0 and 0x80) == 0) throw PgpSshBridgeException("not a packet (byte $b0)")
        val tag = if ((b0 and 0x40) != 0) b0 and 0x3F else (b0 shr 2) and 0x0F
        if (tag != 2) throw PgpSshBridgeException(
            "first packet is not an OpenPGP signature packet (tag $tag, byte $b0)")
        if (parseHeader(data).let { (h, l) -> data.size < h + l })
            throw PgpSshBridgeException("truncated signature packet")
        return data  // full packet: tag + length-encoding + body (parsed next)
    }

    /** Packet header: (headerLength, bodyLength) for OLD- and NEW-format
     *  packet headers. */
    private fun parseHeader(data: ByteArray): Pair<Int, Int> {
        val b0 = data[0].toInt() and 0xFF
        if ((b0 and 0x40) != 0) { // new format
            val lb = data[1].toInt() and 0xFF
            return when {
                lb < 192 -> 2 to lb
                lb in 192..223 -> 3 to ((((lb - 192) shl 8) or (data[2].toInt() and 0xFF)) + 192)
                lb == 255 -> 6 to (((data[2].toInt() and 0xFF) shl 24) or ((data[3].toInt() and 0xFF) shl 16) or
                    ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF))
                else -> throw PgpSshBridgeException("malformed packet length")
            }
        }
        // old format
        val lt = b0 and 0x03
        return when (lt) {
            0 -> 2 to (data[1].toInt() and 0xFF)
            1 -> 3 to (((data[1].toInt() and 0xFF) shl 8) or (data[2].toInt() and 0xFF))
            2 -> 5 to (((data[1].toInt() and 0xFF) shl 24) or ((data[2].toInt() and 0xFF) shl 16) or
                ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF))
            else -> throw PgpSshBridgeException("indeterminate-length packets are unsupported")
        }
    }

    /** Strips the packet header (tag + length), returning the body. */
    private fun parsePacketBody(packet: ByteArray): ByteArray {
        val (hdrLen, bodyLen) = parseHeader(packet)
        return packet.copyOfRange(hdrLen, hdrLen + bodyLen)
    }

    /** The signing key id from an OpenPGP detached signature, taken from
     *  the ISSUER subpacket (type 16) or the ISSUER FINGERPRINT subpacket
     *  (type 33) — scanned in BOTH subpacket areas. Measured against real
     *  gpg/OKK output: the SUBPACKET LENGTH INCLUDES THE TYPE OCTET
     *  (measured sample: len=9, type=16, then the 8-byte key id), so the
     *  value lives at p+2..p+1+len and each area's scan advances by
     *  1 + len. */
    fun issuingKeyId(armored: String): Long? {
        val packet = dearmorFirstSignaturePacket(armored)
        val body = parsePacketBody(packet)
        var issuer: Long? = null
        var issuerFpr: Long? = null
        var p = 4
        val hashedLen = u16(body, p); p += 2 + hashedLen
        val unhashedLen = u16(body, p); p += 2
        val unhashedEnd = p + unhashedLen
        while (p + 2 <= unhashedEnd && p + 2 <= body.size) {
            val lb = body[p].toInt() and 0xFF
            val len: Int
            val hdrLen: Int
            when {
                lb < 192 -> { len = lb; hdrLen = 1 }
                lb < 255 -> { len = ((lb - 192) shl 8) or (body[p + 1].toInt() and 0xFF); hdrLen = 2 }
                else -> { len = ((body[p + 1].toInt() and 0xFF) shl 24) or
                    ((body[p + 2].toInt() and 0xFF) shl 16) or
                    ((body[p + 3].toInt() and 0xFF) shl 8) or
                    (body[p + 4].toInt() and 0xFF); hdrLen = 5 }
            }
            if (p + hdrLen + len > unhashedEnd || p + hdrLen + len > body.size) break
            val type = body[p + hdrLen].toInt() and 0xFF
            // value = body[p+hdrLen+1 .. p+hdrLen+len] (len-1 bytes).
            val valueStart = p + hdrLen + 1
            when (type) {
                16 -> if (len == 9) {
                    issuer = (0 until 8).fold(0L) { acc, k ->
                        (acc shl 8) or (body[valueStart + k].toLong() and 0xFF)
                    }
                }
                33 -> if (len in 22..33) {
                    // value = 1 version byte + fpr; the key id = the fpr's
                    // last 8 bytes = the value's last 8.
                    issuerFpr = (0 until 8).fold(0L) { acc, k ->
                        (acc shl 8) or (body[p + hdrLen + len - 8 + k].toLong() and 0xFF)
                    }
                }
            }
            p += hdrLen + len
        }
        android.util.Log.i("PgpSshBridge",
            "issuingKeyId: issuer=" + (issuer?.let { "%016X".format(it) } ?: "none") +
                ", issuerFpr=" + (issuerFpr?.let { "%016X".format(it) } ?: "none"))
        return issuer ?: issuerFpr ?: run {
            android.util.Log.w("PgpSshBridge", "no issuer subpacket found (unhashed len=$unhashedLen)")
            null
        }
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
