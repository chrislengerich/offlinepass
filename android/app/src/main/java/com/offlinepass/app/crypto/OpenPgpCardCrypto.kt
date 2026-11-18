package com.offlinepass.app.crypto

import org.bouncycastle.bcpg.PublicKeyEncSessionPacket
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
 * ALL the OpenPGP framing — the SEIPD v1 OpenPGP-CFB, the MDC verify,
 * the compressed/literal unpacking, and the envelope construction. No
 * hand-rolled CFB.
 *
 * The seam: [decrypt] takes a `cardDecrypt` lambda (the raw PSO:DEC
 * contract — the PKESK's MPI value in, the PKCS#1 type-2 block out), so
 * the tests substitute a software RSA decrypt and the production wires
 * the YubiKit card op.
 */
object OpenPgpCardCrypto {

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

        var lastError: Exception? = null
        for (pkesk in pkesks) {
            try {
                // The card op OUTSIDE BC's factory machinery: the session
                // key is recovered here (the checksum fast-fails the wrong
                // PKESKs), then BC decrypts with the pre-supplied key —
                // the same decryptor BC itself uses when the session key
                // is already known.
                val (algo, key) = recoverSessionKey(pkesk, cardDecrypt)
                val dataStream = pkesk.getDataStream(
                    BcSessionKeyDataDecryptorFactory(PGPSessionKey(algo, key)))
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

    /**
     * The PKESK → session-key recovery: the card decrypts the PKESK's MPI
     * value, [OpenPgpSeipd.stripType2] strips the PKCS#1 type-2 padding,
     * and the RFC checksum is verified here (the fast-fail for the
     * multi-recipient dispatch — a non-matching card yields garbage, not
     * a session key). Returns (algorithm, session key).
     */
    private suspend fun recoverSessionKey(
        pkesk: PGPPublicKeyEncryptedData,
        cardDecrypt: suspend (ByteArray) -> ByteArray
    ): Pair<Int, ByteArray> {
        val packet = pkeskKeyData(pkesk)
        if (packet.version != 3) {
            throw PGPException("unsupported PKESK version ${packet.version} (the vault uses v3)")
        }
        val m: ByteArray = try {
            OpenPgpSeipd.stripType2(cardDecrypt(mpiValue(packet.encSessionKey[0], packet.version)))
        } catch (e: Exception) {
            throw PGPException("the card decrypt failed: ${e.message}", e)
        }
        if (m.size < 4) throw PGPException("the recovered session data too short")
        val checksum = ((m[m.size - 2].toInt() and 0xFF) shl 8) or
            (m[m.size - 1].toInt() and 0xFF)
        var sum = 0
        for (i in 1 until m.size - 2) sum = (sum + (m[i].toInt() and 0xFF)) and 0xFFFF
        if (sum != checksum) {
            throw PGPException("the session key checksum mismatch — this PKESK is not the card's")
        }
        return (m[0].toInt() and 0xFF) to m.copyOfRange(1, m.size - 2)
    }

    /** BC's PGPPublicKeyEncryptedData hides its packet; the package-private
     *  field is reachable reflectively. The version + the secKeyData come
     *  from it. */
    private fun pkeskKeyData(pkesk: PGPPublicKeyEncryptedData): PublicKeyEncSessionPacket {
        val field = PGPPublicKeyEncryptedData::class.java.getDeclaredField("keyData")
        field.isAccessible = true
        return field.get(pkesk) as PublicKeyEncSessionPacket
    }

    /** The PKESK's secKeyData arrives as the FULL MPI encoding (the
     *  2-byte bit-length prefix + the value) for the v3/v4 packets, and
     *  the 2-byte OCTET-count prefix for the v6 — the card wants the bare
     *  value. Returns the value bytes only. */
    private fun mpiValue(raw: ByteArray, pkeskVersion: Int): ByteArray {
        if (raw.size <= 2) return raw
        val prefix = ((raw[0].toInt() and 0xFF) shl 8) or (raw[1].toInt() and 0xFF)
        val expected = if (pkeskVersion >= 6) prefix else (prefix + 7) / 8
        return if (expected == raw.size - 2) raw.copyOfRange(2, raw.size) else raw
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
     * (a single keyring). Prefers the subkeys; the primary falls back when
     * a key has no encryption subkey (the fixture layout).
     */
    fun loadRecipientKeys(armored: ByteArray): List<PGPPublicKey> {
        val decoder = PGPUtil.getDecoderStream(ByteArrayInputStream(armored))
        val obj = PGPObjectFactory(decoder, JcaKeyFingerprintCalculator()).nextObject()
            ?: throw PGPException("empty key file")
        val ring = obj as? PGPPublicKeyRing
            ?: throw PGPException("not a public key ring: ${obj.javaClass.simpleName}")
        val subkeys = ring.publicKeys.asSequence().filter { it.isEncryptionKey && !it.isMasterKey }
            .toList()
        if (subkeys.isNotEmpty()) return subkeys
        return ring.publicKeys.asSequence().filter { it.isEncryptionKey }.toList()
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
