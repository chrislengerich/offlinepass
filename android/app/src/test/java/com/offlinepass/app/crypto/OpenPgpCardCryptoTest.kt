package com.offlinepass.app.crypto

import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import java.io.ByteArrayInputStream
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

    /** The "card": RSA-decrypts the PKESK's MPI value with the given
     *  secret key — the software stand-in for the YubiKey's PSO:DEC
     *  (the same raw block in/out). The input is left-padded to the
     *  modulus length, exactly like the production YubiKit lambda. */
    private fun softwareCard(secResource: String, keyId: Long): (ByteArray) -> ByteArray {
        return { mpiValue: ByteArray ->
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
            // Left-pad to the modulus length (the MPI may have lost its
            // leading zero via BigInteger normalization).
            val padded = ByteArray(256) { 0 }
            mpiValue.copyInto(padded, 256 - mpiValue.size)
            c.doFinal(padded)
        }
    }

    private fun recipientKeys(vararg resources: String): List<PGPPublicKey> =
        resources.flatMap { OpenPgpCardCrypto.loadRecipientKeys(resource(it)) }

    @Test
    fun decryptsRealGpgFixtureToOriginalPlaintext() {
        val plain = OpenPgpCardCrypto.decrypt(
            resource("fixture-enc.gpg"), longArrayOf(fixtureKeyId), softwareCard("fixture-sec.asc", fixtureKeyId))
        assertEquals(String(resource("fixture-plain.txt")), String(plain))
    }

    @Test
    fun decryptsCompressedGpgFixture() {
        // gpg's default zlib compression — the SEIPD decrypt yields a
        // COMPRESSED packet, not a literal one.
        val plain = OpenPgpCardCrypto.decrypt(
            resource("fixture-enc-zlib.gpg"), longArrayOf(fixtureKeyId), softwareCard("fixture-sec.asc", fixtureKeyId))
        assertEquals(String(resource("fixture-plain.txt")), String(plain))
    }

    @Test
    fun picksTheCardPkeskAmongRecipients() {
        // Two recipients; the card's PKESK is SECOND in the packet order
        // (the second key's comes first) — the dispatch must try it.
        val plain = OpenPgpCardCrypto.decrypt(
            resource("fixture-enc-two.gpg"), longArrayOf(fixtureKeyId), softwareCard("fixture-sec.asc", fixtureKeyId))
        assertEquals(String(resource("fixture-plain.txt")), String(plain))
    }

    @Test
    fun wrongCardFailsCleanly() {
        // The card cannot open ANY PKESK in this message — the result must
        // be a clean failure, never garbage plaintext.
        var failed = false
        try {
            OpenPgpCardCrypto.decrypt(
                resource("fixture-enc.gpg"), longArrayOf(secondKeyId), softwareCard("second-sec.asc", secondKeyId))
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
            OpenPgpCardCrypto.decrypt(
                enc, longArrayOf(fixtureKeyId), softwareCard("fixture-sec.asc", fixtureKeyId))
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
        val back = OpenPgpCardCrypto.decrypt(
            env, longArrayOf(fixtureKeyId), softwareCard("fixture-sec.asc", fixtureKeyId))
        assertArrayEquals(plain, back)
    }

    @Test
    fun otherCardOpensOursToo() {
        // The same envelope, opened by the SECOND recipient's key.
        val recipients = recipientKeys("fixture-pub.asc", "second-pub.asc")
        val plain = "multi-recipient round trip".toByteArray(Charsets.UTF_8)
        val env = OpenPgpCardCrypto.encryptToBytes(plain, "vault.json", recipients)
        val back = OpenPgpCardCrypto.decrypt(
            env, longArrayOf(secondKeyId), softwareCard("second-sec.asc", secondKeyId))
        assertArrayEquals(plain, back)
    }

    @Test
    fun emptyPlaintextRoundTrip() {
        val recipients = recipientKeys("fixture-pub.asc")
        val env = OpenPgpCardCrypto.encryptToBytes(ByteArray(0), "vault.json", recipients)
        val back = OpenPgpCardCrypto.decrypt(
            env, longArrayOf(fixtureKeyId), softwareCard("fixture-sec.asc", fixtureKeyId))
        assertArrayEquals(ByteArray(0), back)
    }
}
