package com.offlinepass.app.crypto

import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.PGPDataDecryptor
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

/**
 * The BC-backed OpenPGP crypto for the card path: the card (YubiKey or a
 * software stand-in) recovers the session key; BouncyCastle's bcpg does
 * ALL the OpenPGP framing — the checksum confirm, the SEIPD v1
 * OpenPGP-CFB, the MDC verify, the compressed/literal unpacking, and the
 * envelope construction. No hand-rolled CFB, no reflection on BC
 * internals (R8-safe).
 *
 * The seam: [decrypt] takes a `cardDecrypt` lambda (the raw PSO:DEC
 * contract — the PKESK's MPI value in, the PKCS#1 type-2 block out), so
 * the tests substitute a software RSA decrypt and the production wires
 * the YubiKit card op.
 */
object OpenPgpCardCrypto {

    /** The KEY FLAGS bits (RFC 4880 §5.2.3.21) that grant OpenPGP
     *  encryption: 0x04 = encrypt-communications, 0x08 = encrypt-storage. */
    private const val KEY_FLAG_ENCRYPT = 0x04 or 0x08

    /**
     * The card-in-the-middle decryptor: BC hands the PKESK's encrypted
     * session key here, we run the card op (blocking — the call chain is
     * on Dispatchers.IO; the touch prompt stays responsive on Main) and
     * strip the PKCS#1 type-2 padding. BC's getSessionKey then verifies
     * the RFC checksum (the fast-fail for the multi-recipient dispatch —
     * a non-matching card yields garbage, not a session key) and extracts
     * the algorithm + key per the packet version — all of it BC's own
     * code, no reflection on package-private internals.
     */
    class CardPublicKeyDecryptorFactory(
        private val cardDecrypt: suspend (ByteArray) -> ByteArray,
    ) : AbstractPublicKeyDataDecryptorFactory() {

        override fun recoverSessionData(
            keyAlgorithm: Int,
            secKeyData: Array<ByteArray>,
            pkeskVersion: Int
        ): ByteArray {
            val raw = try {
                // runBlocking: the call chain is synchronous (BC's) and
                // lives on Dispatchers.IO — the card op blocks this thread
                // either way; the touch prompt renders on Main.
                kotlinx.coroutines.runBlocking {
                    cardDecrypt(mpiValue(secKeyData[0], pkeskVersion))
                }
            } catch (e: Exception) {
                throw PGPException("the card decrypt failed: ${e.message}", e)
            }
            // TWO RESPONSE SHAPES: the classic cards return the full PKCS#1
            // type-2 block (00 02 PS 00 M — strip it); the newer YubiKey
            // applets return the ALREADY-UNPADDED session data M
            // (algo || key || checksum — see YubiKit's "decrypted and
            // unpadded plaintext"). The sizes never collide: a padded
            // block = the modulus length (256+), M ≤ the key size + 3.
            val m = if (raw.size > 128) try {
                OpenPgpSeipd.stripType2(raw)
            } catch (e: Exception) {
                throw PGPException("the card decrypt failed: not a type-2 block (a ${raw.size}B response)", e)
            } else raw
            if (m.size < 4) throw PGPException("the recovered session data too short")
            return m
        }

        /** The PKESK's encrypted session key arrives as the FULL MPI
         *  encoding (the 2-byte bit-length prefix + the value) for the
         *  v3/v4 packets, and the 2-byte OCTET-count prefix for the v6 —
         *  the card wants the bare value. Returns the value bytes only. */
        private fun mpiValue(raw: ByteArray, pkeskVersion: Int): ByteArray {
            if (raw.size <= 2) return raw
            val prefix = ((raw[0].toInt() and 0xFF) shl 8) or (raw[1].toInt() and 0xFF)
            val expected = if (pkeskVersion >= 6) prefix else (prefix + 7) / 8
            return if (expected == raw.size - 2) raw.copyOfRange(2, raw.size) else raw
        }

        override fun createDataDecryptor(
            forEncryption: Boolean,
            encAlgorithm: Int,
            key: ByteArray
        ): PGPDataDecryptor = BcSessionKeyDataDecryptorFactory(PGPSessionKey(encAlgorithm, key))
            .createDataDecryptor(forEncryption, encAlgorithm, key)

        // The v5/v6 AEAD overloads — unused on this path (the vault files
        // are SEIPD v1), delegated to BC's own implementation.
        override fun createDataDecryptor(
            aeadEncData: org.bouncycastle.bcpg.AEADEncDataPacket,
            sessionKey: PGPSessionKey
        ): PGPDataDecryptor =
            BcSessionKeyDataDecryptorFactory(sessionKey).createDataDecryptor(aeadEncData, sessionKey)

        override fun createDataDecryptor(
            integrityPacket: org.bouncycastle.bcpg.SymmetricEncIntegrityPacket,
            sessionKey: PGPSessionKey
        ): PGPDataDecryptor =
            BcSessionKeyDataDecryptorFactory(sessionKey).createDataDecryptor(integrityPacket, sessionKey)
    }

    /**
     * Decrypts an OpenPGP message (the armored or the binary) whose
     * recipients include the card's key, returning the original plaintext.
     *
     * [preferredCardKeyIds] orders the PKESK dispatch — the card's own
     * PKESK first, so a multi-recipient envelope costs exactly one card
     * op. Any PKESK the card cannot open (the checksum mismatch, the
     * malformed padding) fails fast and the next candidate is tried; a
     * card with no matching PKESK at all fails cleanly.
     */
    suspend fun decrypt(
        msgBytes: ByteArray,
        preferredCardKeyIds: LongArray = LongArray(0),
        cardDecrypt: suspend (ByteArray) -> ByteArray
    ): ByteArray {
        val decoder = PGPUtil.getDecoderStream(ByteArrayInputStream(msgBytes))
        val factory = PGPObjectFactory(decoder, JcaKeyFingerprintCalculator())
        val encList = findEncryptedDataList(factory)
            ?: throw PGPException("no encrypted data in the message")
        val pkesks = encList.filterIsInstance<PGPPublicKeyEncryptedData>().toMutableList()
            .sortedBy { pkesk ->
                // The card's own PKESKs first; the others keep their order.
                val idx = preferredCardKeyIds.indexOf(pkesk.keyID)
                if (idx >= 0) idx else preferredCardKeyIds.size
            }
        if (pkesks.isEmpty()) throw PGPException("no PKESK in the message")

        val cardFactory = CardPublicKeyDecryptorFactory(cardDecrypt)
        var lastError: Exception? = null
        for (pkesk in pkesks) {
            try {
                // BC recovers the session key THROUGH the card (the factory
                // runs the card op + the strip; BC confirms the checksum —
                // a wrong PKESK throws here) and then decrypts the SEIPD.
                val sessionKey = pkesk.getSessionKey(cardFactory)
                val dataStream = pkesk.getDataStream(
                    BcSessionKeyDataDecryptorFactory(sessionKey))
                val plain = unpack(dataStream)
                // The MDC verification: BC's verify() drains the stream and
                // RETURNS the verdict (it does not throw) — a tampered
                // message must fail the decrypt, never pass through.
                if (!pkesk.verify()) {
                    throw PGPException("the MDC check failed — the message may be tampered")
                }
                return plain
            } catch (e: PGPException) {
                lastError = e
            } catch (e: Exception) {
                lastError = PGPException("the decrypt failed: ${e.message}", e)
            }
        }
        throw PGPException(
            "the card opens none of the ${pkesks.size} recipient(s): " +
                (lastError?.message ?: "unknown"), lastError)
    }

    /** THE VAULT→CARD PRE-CHECK: the recipient key ids of an OpenPGP
     *  message's PKESKs — a pure parse, no card, no secrets. The unlock
     *  path reads this BEFORE the PIN verify: a wrong card fails by name
     *  instead of burning a PIN attempt on a decrypt that can never open. */
    fun pkeskKeyIds(msgBytes: ByteArray): List<Long> {
        val decoder = PGPUtil.getDecoderStream(ByteArrayInputStream(msgBytes))
        val factory = PGPObjectFactory(decoder, JcaKeyFingerprintCalculator())
        val encList = findEncryptedDataList(factory)
            ?: throw PGPException("no encrypted data in the message")
        val ids = encList.filterIsInstance<PGPPublicKeyEncryptedData>().map { it.keyID }
        if (ids.isEmpty()) throw PGPException("no PKESK in the message")
        return ids
    }

    /** Builds a v4 RSA public-key packet from the RAW key material — the
     *  card's DEC slot exposes only the (n, e); the creation time rides
     *  the card's own DO (the seconds). The fingerprint = computed over
     *  the packet — identical to the card's reported one when the time
     *  matches (the OpenPGP v4 fingerprint = over version|algo|time|n|e). */
    fun recipientKeyFromRaw(
        modulus: java.math.BigInteger,
        exponent: java.math.BigInteger,
        creationSecs: Int
    ): PGPPublicKey {
        val packet = org.bouncycastle.bcpg.PublicKeyPacket(
            org.bouncycastle.bcpg.PublicKeyAlgorithmTags.RSA_GENERAL,
            java.util.Date(creationSecs * 1000L),
            org.bouncycastle.bcpg.RSAPublicBCPGKey(modulus, exponent))
        return PGPPublicKey(packet, JcaKeyFingerprintCalculator())
    }

    /** The armored (the ASCII-armored public-key packet) form of a key —
     *  the repo's record of a recipient. */
    fun armoredKey(key: PGPPublicKey): String {
        val out = java.io.ByteArrayOutputStream()
        org.bouncycastle.bcpg.ArmoredOutputStream(out).use { a ->
            a.write(key.encoded)
        }
        return out.toString(Charsets.ISO_8859_1.name())
    }

    /** Walks the decrypted stream: the compressed packets recurse, the
     *  literal packet yields the content. Returns the plaintext bytes. */
    internal fun unpack(dataStream: java.io.InputStream): ByteArray {
        val objFactory = PGPObjectFactory(dataStream, JcaKeyFingerprintCalculator())
        var obj = objFactory.nextObject()
        while (obj != null) {
            when (obj) {
                is PGPCompressedData -> {
                    val inner = PGPObjectFactory(obj.dataStream, JcaKeyFingerprintCalculator())
                    var innerObj = inner.nextObject()
                    while (innerObj != null) {
                        if (innerObj is PGPLiteralData) {
                            return innerObj.inputStream.readBytes()
                        }
                        innerObj = inner.nextObject()
                    }
                    throw PGPException("no literal data inside the compressed packet")
                }
                is PGPLiteralData -> return obj.inputStream.readBytes()
            }
            obj = objFactory.nextObject()
        }
        throw PGPException("no literal data in the decrypted stream")
    }

    private fun findEncryptedDataList(factory: PGPObjectFactory): PGPEncryptedDataList? {
        var obj = factory.nextObject()
        while (obj != null) {
            if (obj is PGPEncryptedDataList) return obj
            obj = factory.nextObject()
        }
        return null
    }

    /**
     * Loads the encryption-capable public keys from an armored key file
     * (a single keyring). The KEY FLAGS rule (RFC 4880 §5.2.3.21):
     * "encryption-capable" = the flag bits 0x04/0x08 in the self-signatures
     * — NOT the algorithm. BC's [PGPPublicKey.isEncryptionKey] reports true
     * for EVERY RSA subkey regardless of its flags, so the old
     * algorithm-based filter once sealed the vault to the SIGN/AUTH
     * subkeys of [CE]-primary keys (the primaries — the only keys
     * anything could open — were excluded; the repo mode's vault became
     * unreadable until the seal was redone).
     *
     * Preference: the encryption-flagged SUBKEY, then the
     * encryption-flagged primary (the [CE]-only layout), then — only when
     * the ring carries NO flags at all (the RFC default = all
     * capabilities, e.g. the card-constructed bare keys) — the
     * algorithm-level check.
     */
    fun loadRecipientKeys(armored: ByteArray): List<PGPPublicKey> {
        val decoder = PGPUtil.getDecoderStream(ByteArrayInputStream(armored))
        val obj = PGPObjectFactory(decoder, JcaKeyFingerprintCalculator()).nextObject()
            ?: throw PGPException("empty key file")
        val ring = obj as? PGPPublicKeyRing
            ?: throw PGPException("not a public key ring: ${obj.javaClass.simpleName}")
        val keys = ring.publicKeys.asSequence().toList()
        // A ring that expresses NO flags at all (the card-constructed bare
        // keys) falls back to the RFC default — the algorithm-level check.
        if (keys.none { keyFlags(it) != 0 }) return keys.filter { it.isEncryptionKey }
        fun flagged(subkey: Boolean) = keys.filter {
            (if (subkey) !it.isMasterKey else it.isMasterKey) &&
                (keyFlags(it) and KEY_FLAG_ENCRYPT) != 0
        }
        flagged(subkey = true).takeIf { it.isNotEmpty() }?.let { return it }
        flagged(subkey = false).takeIf { it.isNotEmpty() }?.let { return it }
        // The ring carries flags but grants no encryption (a sign-only
        // layout) — sealing to it would produce PKESKs nothing can open.
        throw PGPException(
            "the key ring grants no encryption capability (the KEY FLAGS " +
                "certify/sign/auth only) — re-export the recipient key")
    }

    /** The union of the KEY FLAGS subpackets across a key's signatures
     *  (0 = no flags information — the caller falls back to the RFC
     *  default). */
    private fun keyFlags(key: PGPPublicKey): Int {
        var flags = 0
        val sigs = key.signatures
        while (sigs.hasNext()) flags = flags or sigs.next().hashedSubPackets.keyFlags
        return flags
    }

    /**
     * Encrypts [plain] to [recipients] (OpenPGP binary output, no
     * signing): AES-256 SEIPD v1 with the MDC — matching what gpg/OKK
     * produce, so any OpenPGP implementation can recover it.
     */
    fun encryptToBytes(
        plain: ByteArray,
        filename: String,
        recipients: List<PGPPublicKey>
    ): ByteArray {
        require(recipients.isNotEmpty()) { "no recipients" }
        val encGen = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(SecureRandom()))
        for (key in recipients) {
            encGen.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(key))
        }
        val out = ByteArrayOutputStream()
        // The streaming (partial-length) opens (the buffer argument = the
        // unknown-length mode): passing a known length makes BC miscompute
        // the SEIPD packet size (the literal header + the MDC are not part
        // of [plain]). gpg + BC both read the partial-length packets fine.
        val buf = ByteArray(1 shl 16)
        encGen.open(out, ByteArray(1 shl 16)).use { encOut ->
            PGPLiteralDataGenerator().open(
                encOut, PGPLiteralData.BINARY, filename, Date(), buf
            ).use { litOut ->
                litOut.write(plain)
            }
        }
        return out.toByteArray()
    }
}
