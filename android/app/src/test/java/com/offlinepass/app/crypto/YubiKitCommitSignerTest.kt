package com.offlinepass.app.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey

/**
 * YubiKitCommitSigner end-to-end without hardware: the injected cardSign
 * is the software SIG-slot model (pad the bare DigestInfo on-"card", raw
 * RSA), and the produced armored signature must verify under BouncyCastle
 * like gpg would. Also pins the PIN behavior: remembered ONLY on success,
 * and a cancelled prompt or a failed card op aborts the commit with a
 * readable error.
 */
class YubiKitCommitSignerTest {

    init {
        java.security.Security.addProvider(
            org.bouncycastle.jce.provider.BouncyCastleProvider())
    }

    private val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val context = org.mockito.Mockito.mock(android.content.Context::class.java)

    /** The card: PKCS#1 v1.5 pad the DigestInfo on-"card", raw RSA. */
    private fun simulateCardSign(
        di: ByteArray,
        privateKey: java.security.PrivateKey,
    ): ByteArray {
        val modSize = ((kp.public as RSAPublicKey).modulus.bitLength() + 7) / 8
        val pad = modSize - di.size - 3
        val block = byteArrayOf(0x00, 0x01) + ByteArray(pad) { 0xFF.toByte() } +
            byteArrayOf(0x00) + di
        val c = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding")
        c.init(javax.crypto.Cipher.DECRYPT_MODE, privateKey)
        return c.doFinal(block)
    }

    private val content = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n".toByteArray()

    private fun verify(armored: String, payload: ByteArray): Boolean {
        val decoded = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(armored.byteInputStream())
        val factory = org.bouncycastle.openpgp.PGPObjectFactory(
            decoded, org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator())
        val sig = (factory.nextObject() as org.bouncycastle.openpgp.PGPSignatureList)[0]
        val pk = org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter()
            .getPGPPublicKey(org.bouncycastle.bcpg.PublicKeyAlgorithmTags.RSA_GENERAL,
                kp.public, java.util.Date())
        sig.init(
            org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider()
                .setProvider("BC"), pk)
        sig.update(payload)
        return sig.verify()
    }

    @Test
    fun signedCommitVerifiesAndPinIsRememberedOnSuccess() = kotlinx.coroutines.runBlocking {
        val prompts = mutableListOf<String>()
        var remembered: CharArray? = null
        val signer = YubiKitCommitSigner(
            context = context,
            keyId = -0x63DF668CC4E7B53L,  // 0x63EBEE3E00698013 unsigned
            prompt = { "123456".toCharArray().also { prompts += it.concatToString() } },
            rememberPin = { remembered = it.copyOf() },
            cardSign = { pin, payload ->
                // The card receives the BARE DigestInfo of the v4 hash
                // (content+trailer): 19-byte SHA-256 prefix + 32-byte
                // digest = 51 bytes.
                assertEquals(51, payload.size)
                assertEquals(0x30.toByte(), payload[0])
                assertEquals("123456", pin.concatToString())
                simulateCardSign(payload, kp.private)
            })
        val gpg = signer.sign(null, null, content, null, null, null)
        val armored = gpg.toExternalString()
        assertTrue("the commit signature must verify", verify(armored, content))
        assertEquals(1, prompts.size) // the prompt ran once
        assertEquals("123456", remembered!!.concatToString())
    }

    @Test
    fun cancelledPinAbortsTheCommitWithAReadableError() = kotlinx.coroutines.runBlocking {
        val signer = YubiKitCommitSigner(
            context = context, keyId = 1L,
            prompt = { null },
            cardSign = { _, _ -> byteArrayOf(1) })
        try {
            signer.sign(null, null, content, null, null, null)
            throw AssertionError("a cancelled PIN must abort the commit")
        } catch (e: java.io.IOException) {
            assertEquals("OpenPGP PIN cancelled — commit aborted", e.message)
        }
    }

    @Test
    fun cardFailureSurfacesAndDoesNotRememberThePin() = kotlinx.coroutines.runBlocking {
        var remembered: CharArray? = null
        val signer = YubiKitCommitSigner(
            context = context, keyId = 1L,
            prompt = { "654321".toCharArray() },
            rememberPin = { remembered = it.copyOf() },
            cardSign = { _, _ -> throw java.io.IOException("Wrong PIN — 2 attempt(s) remaining") })
        try {
            signer.sign(null, null, content, null, null, null)
            throw AssertionError("a failed card op must abort the commit")
        } catch (e: java.io.IOException) {
            assertTrue(e.message!!.contains("Wrong PIN"))
        }
        assertEquals("a FAILED sign must not remember the pin", null, remembered)
    }

    @Test
    fun ed25519SlotSignsTheFullMaterialAndBCVerifies() = kotlinx.coroutines.runBlocking {
        // The cv25519 SIG slot = Ed25519: the slot probe answers ED25519,
        // the card PureEdDSAs the FULL SIGNED MATERIAL (no DigestInfo),
        // the packet = alg 22 — and BC 1.87 must verify the armored
        // result (the gpg path).
        val ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        var sawMaterial: ByteArray? = null
        val signer = YubiKitCommitSigner(
            context = context,
            keyId = -0x63DF668CC4E7B53L,
            prompt = { "123456".toCharArray() },
            slotKeyProbe = { "ED25519" },
            cardSign = { _, material ->
                sawMaterial = material
                val s = java.security.Signature.getInstance("Ed25519")
                s.initSign(ed.private)
                s.update(material)
                s.sign()
            })
        val gpg = signer.sign(null, null, content, null, null, null)
        val armored = gpg.toExternalString()

        // The card saw the DIGEST (the card-spec EdDSA PSO:CDS: the host
        // hashes — the payload = the raw 32-byte SHA-256 digest of the
        // signed material, not the 51-byte RSA DigestInfo, not the doc).
        assertTrue("the card must see the 32-byte digest",
            sawMaterial!!.size == 32)

        // The BC verification: the EDDSA tag + the real key.
        val decoded = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(
            armored.byteInputStream())
        val factory = org.bouncycastle.openpgp.PGPObjectFactory(
            decoded, org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator())
        val sig = (factory.nextObject() as org.bouncycastle.openpgp.PGPSignatureList)[0]
        assertEquals(org.bouncycastle.bcpg.PublicKeyAlgorithmTags.EDDSA, sig.keyAlgorithm)
        val pk = org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter()
            .getPGPPublicKey(org.bouncycastle.bcpg.PublicKeyAlgorithmTags.EDDSA,
                ed.public, java.util.Date())
        sig.init(
            org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider()
                .setProvider("BC"), pk)
        sig.update(content)
        assertTrue("BC must verify the Ed25519 commit signature", sig.verify())
    }
}
