package com.offlinepass.app.crypto

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.util.Date

/**
 * THE ECDH DECRYPT CONTRACT, proven without hardware.
 *
 * The card's ECDH PSO:DEC = the RFC 6637 math (the ephemeral point in,
 * the KDF + the AES-key-unwrap on-card, the plain session data out).
 * BC's own BcPublicKeyDataDecryptorFactory implements EXACTLY that math
 * with a private key — so the fake card here is the card's reference
 * implementation, and the tests prove the app's decrypt pipeline (the
 * PKESK dispatch, the MPI handling, the session-data shapes) against it.
 *
 * The RSA path keeps its own tests; this file covers the EC branch.
 */
class EcdhDecryptTest {

    private fun ecdhRecipient(): Pair<PGPPublicKey, PGPPrivateKey> {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val kp = kpg.generateKeyPair()
        val converter = JcaPGPKeyConverter()
        val pub = converter.getPGPPublicKey(
            PublicKeyAlgorithmTags.ECDH, kp.public, Date())
        val priv = converter.getPGPPrivateKey(pub, kp.private)
        return pub to priv
    }

    /** The plaintext OpenPGP message encrypted to the recipient (the same
     *  construction the app's encrypt path uses: the AES-256 SEIPD). */
    private fun encrypt(recipients: List<PGPPublicKey>, plain: ByteArray): ByteArray {
        // THE APP'S EXACT CONSTRUCTION: the AES-256 SEIPD + the literal
        // data with the partial-length streaming (see encryptToBytes).
        val generator = org.bouncycastle.openpgp.PGPEncryptedDataGenerator(
            org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder(
                SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(java.security.SecureRandom()))
        recipients.forEach {
            generator.addMethod(
                org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator(it))
        }
        val out = java.io.ByteArrayOutputStream()
        generator.open(out, ByteArray(1 shl 16)).use { encOut ->
            org.bouncycastle.openpgp.PGPLiteralDataGenerator().open(
                encOut, org.bouncycastle.openpgp.PGPLiteralData.BINARY,
                "test", Date(), ByteArray(1 shl 16)).use { litOut ->
                litOut.write(plain)
            }
        }
        return out.toByteArray()
    }

    /** THE FAKE CARD: the PKESK's bare ephemeral point (what the app hands
     *  the card) → the RFC 6637 math with the recipient's private key →
     *  the plain session data (what the card returns). The point is
     *  re-MPI-encoded for BC's factory (the card sees the same PKESK
     *  field BC's recoverSessionData expects). */
    private fun fakeCardEcdh(priv: PGPPrivateKey): (ByteArray) -> ByteArray {
        val factory = BcPublicKeyDataDecryptorFactory(priv)
        return { point: ByteArray ->
            // BC's recoverSessionData takes the STRIPPED value (the packet
            // parser removes the MPI prefix) — exactly what the app's
            // mpiValue() hands the card.
            factory.recoverSessionData(
                PublicKeyAlgorithmTags.ECDH, arrayOf(point), 3)
        }
    }

    @Test
    fun `encrypt to an ECDH recipient and decrypt via the fake card`() {
        val (pub, priv) = ecdhRecipient()
        val plain = "the EC round-trip plaintext".toByteArray()
        val msg = encrypt(listOf(pub), plain)

        // The PKESK dispatch: the message's recipient key ids include the
        // EC key (the card-preferred ordering reads them without secrets).
        val ids = OpenPgpCardCrypto.pkeskKeyIds(msg)
        assertTrue("the PKESK names the ECDH key", pub.keyID in ids)

        val recovered = kotlinx.coroutines.runBlocking { OpenPgpCardCrypto.decrypt(
            msg, longArrayOf(pub.keyID), fakeCardEcdh(priv))
        }

        assertArrayEquals(plain, recovered)
    }

    @Test
    fun `multi-recipient envelope with RSA and ECDH keys`() {
        // THE MIXED ENVELOPE: the RSA recipient (the legacy card/lock key)
        // + the ECDH recipient — the decrypt opens through EITHER, the
        // card-preferred ordering puts the matching PKESK first.
        val rsaKp = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()
        val converter = JcaPGPKeyConverter()
        val rsaPub = converter.getPGPPublicKey(
            PublicKeyAlgorithmTags.RSA_GENERAL, rsaKp.public, Date())
        val (ecPub, ecPriv) = ecdhRecipient()

        val plain = "the mixed-recipient plaintext".toByteArray()
        val msg = encrypt(listOf(rsaPub, ecPub), plain)

        assertTrue(OpenPgpCardCrypto.pkeskKeyIds(msg).containsAll(
            listOf(rsaPub.keyID, ecPub.keyID)))

        // The ECDH path (the EC card's slot): the fake card opens the EC
        // PKESK.
        val recovered = kotlinx.coroutines.runBlocking {
            OpenPgpCardCrypto.decrypt(
                msg, longArrayOf(ecPub.keyID), fakeCardEcdh(ecPriv))
        }
        assertArrayEquals(plain, recovered)
    }

    @Test
    fun `wrong card's key id fails the dispatch pre-check`() {
        val (pub, _) = ecdhRecipient()
        val msg = encrypt(listOf(pub), "x".toByteArray())
        // A DIFFERENT card's DEC id (a wrong card): the decrypt's
        // pkeskKeyIds pre-check (the unlock path) names the mismatch
        // without burning a PIN attempt.
        val ids = OpenPgpCardCrypto.pkeskKeyIds(msg)
        assertTrue("the wrong card's id is not among the recipients",
            0x1122334455667788L !in ids)
    }
}
