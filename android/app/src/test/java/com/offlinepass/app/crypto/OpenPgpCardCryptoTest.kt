package com.offlinepass.app.crypto

import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.Security

/**
 * THE ORACLE TESTS for the BC-based card decrypt + encrypt
 * ([OpenPgpCardCrypto]): the card op is a SOFTWARE RSA decrypt (the
 * fixture secret keys, parsed by BC — the same raw block in/out as the
 * YubiKey's PSO:DEC), and the OpenPGP framing (the CFB, the MDC, the
 * literal/compressed unpacking, the PKESK construction) is BouncyCastle's
 * bcpg. Every test oracle = a REAL gpg 2.4.7-produced message.
 */
class OpenPgpCardCryptoTest {

    init {
        Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
    }

    private fun resource(name: String): ByteArray =
        javaClass.getResourceAsStream("/openpgp/$name")!!.readBytes()

    /** The fixture primary key (RSA-2048, encryption-capable). */
    private val fixtureKeyId = 0x1EA759B8783363D8UL.toLong()
    /** The second fixture key ("second@fixture.test"). */
    private val secondKeyId = 0x4199727F7793732FUL.toLong()

    /** The "card" (the CLASSIC shape): RSA-decrypts the PKESK's MPI value
     *  and returns the full PKCS#1 type-2 block — the same raw block in/out
     *  as the older YubiKey applets' PSO:DEC. The input is left-padded to
     *  the modulus length, exactly like the production YubiKit lambda. */
    private fun softwareCard(secResource: String, keyId: Long): (ByteArray) -> ByteArray {
        return { mpiValue: ByteArray ->
            val padded = ByteArray(256) { 0 }
            mpiValue.copyInto(padded, 256 - mpiValue.size)
            softwareRsaDecrypt(secResource, keyId, padded)
        }
    }

    /** The "newer applet" card: returns the ALREADY-UNPADDED session data
     *  M (algo || key || checksum) instead of the PKCS#1 type-2 block —
     *  YubiKit's "decrypted and unpadded plaintext" shape. */
    private fun softwareCardUnpadded(secResource: String, keyId: Long): (ByteArray) -> ByteArray {
        return { mpiValue: ByteArray ->
            val padded = ByteArray(256) { 0 }
            mpiValue.copyInto(padded, 256 - mpiValue.size)
            com.offlinepass.app.crypto.OpenPgpSeipd.stripType2(
                softwareRsaDecrypt(secResource, keyId, padded))
        }
    }

    private fun softwareRsaDecrypt(
        secResource: String,
        keyId: Long,
        input: ByteArray
    ): ByteArray {
        val decoded = PGPUtil.getDecoderStream(resource(secResource).inputStream())
        val ring = PGPObjectFactory(decoded, JcaKeyFingerprintCalculator()).nextObject()
                as PGPSecretKeyRing
        val sk = ring.getSecretKey(keyId.toLong())
            ?: throw IllegalStateException("the fixture key 0x${keyId.toString(16)} is missing")
        val privJca = org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter().getPrivateKey(
            sk.extractPrivateKey(
                JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(charArrayOf())))
        val c = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding")
        c.init(javax.crypto.Cipher.DECRYPT_MODE, privJca)
        return c.doFinal(input)
    }

    private fun recipientKeys(vararg resources: String): List<org.bouncycastle.openpgp.PGPPublicKey> =
        resources.flatMap { OpenPgpCardCrypto.loadRecipientKeys(resource(it)) }

    @Test
    fun decryptsRealGpgFixtureToOriginalPlaintext() {
        val plain = runBlocking {
            OpenPgpCardCrypto.decrypt(
                resource("fixture-enc.gpg"), longArrayOf(fixtureKeyId),
                softwareCard("fixture-sec.asc", fixtureKeyId))
        }
        assertEquals(String(resource("fixture-plain.txt")), String(plain))
    }

    @Test
    fun decryptsCompressedGpgFixture() {
        // gpg's default zlib compression — the SEIPD decrypt yields a
        // COMPRESSED packet, not a literal one.
        val plain = runBlocking {
            OpenPgpCardCrypto.decrypt(
                resource("fixture-enc-zlib.gpg"), longArrayOf(fixtureKeyId),
                softwareCard("fixture-sec.asc", fixtureKeyId))
        }
        assertEquals(String(resource("fixture-plain.txt")), String(plain))
    }

    @Test
    fun picksTheCardPkeskAmongRecipients() {
        // Two recipients; the card's PKESK is SECOND in the packet order
        // (the second key's comes first) — the dispatch must try it.
        val plain = runBlocking {
            OpenPgpCardCrypto.decrypt(
                resource("fixture-enc-two.gpg"), longArrayOf(fixtureKeyId),
                softwareCard("fixture-sec.asc", fixtureKeyId))
        }
        assertEquals(String(resource("fixture-plain.txt")), String(plain))
    }

    @Test
    fun wrongCardFailsCleanly() {
        // The card cannot open ANY PKESK in this message — the result must
        // be a clean failure, never garbage plaintext.
        var failed = false
        try {
            runBlocking {
                OpenPgpCardCrypto.decrypt(
                    resource("fixture-enc.gpg"), longArrayOf(secondKeyId),
                    softwareCard("second-sec.asc", secondKeyId))
            }
        } catch (e: Exception) {
            failed = true
        }
        assertEquals(true, failed)
    }

    @Test
    fun unpaddedResponseShapeStillDecrypts() {
        // The newer YubiKey applets return the ALREADY-UNPADDED session
        // data (M = algo || key || checksum) instead of the PKCS#1 block —
        // the factory must accept both shapes.
        val plain = runBlocking {
            OpenPgpCardCrypto.decrypt(
                resource("fixture-enc.gpg"), longArrayOf(fixtureKeyId),
                softwareCardUnpadded("fixture-sec.asc", fixtureKeyId))
        }
        assertEquals(String(resource("fixture-plain.txt")), String(plain))
    }

    @Test
    fun unpaddedShapeWrongCardFailsCleanly() {
        // The unpadded shape from a card that owns no PKESK: the checksum
        // check must reject the garbage session data cleanly.
        var failed = false
        try {
            runBlocking {
                OpenPgpCardCrypto.decrypt(
                    resource("fixture-enc.gpg"), longArrayOf(fixtureKeyId),
                    softwareCardUnpadded("second-sec.asc", secondKeyId))
            }
        } catch (e: Exception) {
            failed = true
        }
        assertEquals(true, failed)
    }

    @Test
    fun tamperedCiphertextFailsMdc() {
        val enc = resource("fixture-enc.gpg").copyOf()
        enc[enc.size - 5] = (enc[enc.size - 5].toInt() xor 1).toByte()
        var failed = false
        try {
            runBlocking {
                OpenPgpCardCrypto.decrypt(
                    enc, longArrayOf(fixtureKeyId), softwareCard("fixture-sec.asc", fixtureKeyId))
            }
        } catch (e: Exception) {
            failed = true
        }
        assertEquals(true, failed)
    }

    @Test
    fun roundTripOursEncryptOursDecrypt() {
        val recipients = recipientKeys("fixture-pub.asc", "second-pub.asc")
        assertEquals("both recipient keys must load", 2, recipients.size)
        val plain = "the vault envelope JSON — секрет, mot de passe ✅".toByteArray(Charsets.UTF_8)
        val env = OpenPgpCardCrypto.encryptToBytes(plain, "vault.json", recipients)
        val back = runBlocking {
            OpenPgpCardCrypto.decrypt(
                env, longArrayOf(fixtureKeyId), softwareCard("fixture-sec.asc", fixtureKeyId))
        }
        assertArrayEquals(plain, back)
    }

    @Test
    fun otherCardOpensOursToo() {
        // The same envelope, opened by the SECOND recipient's key.
        val recipients = recipientKeys("fixture-pub.asc", "second-pub.asc")
        val plain = "multi-recipient round trip".toByteArray(Charsets.UTF_8)
        val env = OpenPgpCardCrypto.encryptToBytes(plain, "vault.json", recipients)
        val back = runBlocking {
            OpenPgpCardCrypto.decrypt(
                env, longArrayOf(secondKeyId), softwareCard("second-sec.asc", secondKeyId))
        }
        assertArrayEquals(plain, back)
    }

    @Test
    fun emptyPlaintextRoundTrip() {
        val recipients = recipientKeys("fixture-pub.asc")
        val env = OpenPgpCardCrypto.encryptToBytes(ByteArray(0), "vault.json", recipients)
        val back = runBlocking {
            OpenPgpCardCrypto.decrypt(
                env, longArrayOf(fixtureKeyId), softwareCard("fixture-sec.asc", fixtureKeyId))
        }
        assertArrayEquals(ByteArray(0), back)
    }
}
