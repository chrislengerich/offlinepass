package com.offlinepass.app.crypto

import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.Security

/**
 * THE ORACLE TEST: decrypt a REAL gpg 2.4.7-produced OpenPGP message
 * (fixture-enc.gpg, encrypted to the fixture test key) through the
 * complete card path — the PKESK, the PKCS#1 type-2 strip, the
 * OpenPGP-CFB with the resync, the MDC verify, the literal unpack — and
 * yield the original plaintext byte-for-byte. The card op is a SOFTWARE
 * RSA decrypt using the fixture test key's secret (the exported
 * fixture-sec.asc, parsed by BouncyCastle).
 */
class OpenPgpSeipdFixtureTest {

    init {
        Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
    }

    private fun resource(name: String): ByteArray =
        javaClass.getResourceAsStream("/openpgp/$name")!!.readBytes()

    /** The "card": RSA-decrypts the PKESK's MPI value with the fixture
     *  test key's secret — the software stand-in for the YubiKey's
     *  PSO:DEC (the same raw block in, the raw block out). */
    private val cardDecrypt: (ByteArray) -> ByteArray by lazy {
        val decryptFn: (ByteArray) -> ByteArray = { mpiValue: ByteArray ->
            val decoded = PGPUtil.getDecoderStream(resource("fixture-sec.asc").inputStream())
            val factory = PGPObjectFactory(decoded, JcaKeyFingerprintCalculator())
            val ring = factory.nextObject() as PGPSecretKeyRing
            // The export-secret-subkeys output carries a GNU-dummy stub for
            // the primary — pick the ENCRYPTION SUBKEY by its key id.
            val sk = ring.getSecretKey(0x1EA759B8783363D8UL.toLong())
                ?: throw IllegalStateException("the fixture subkey is missing")
            val privJca = org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter().getPrivateKey(
                sk.extractPrivateKey(
                    JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(charArrayOf())))
            // The RAW contract: NoPadding = the raw EM (the padded block),
            // matching the card's PSO:DEC response shape.
            val c = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding")
            c.init(javax.crypto.Cipher.DECRYPT_MODE, privJca)
            c.doFinal(mpiValue)
        }
        decryptFn
    }

    /** The KNOWN session key (from gpg --show-session-key): isolates the
     *  CFB from the PKESK decrypt. */
    private val knownSessionKey = org.bouncycastle.util.encoders.Hex.decodeStrict(
        "4526B823540086687CFB3CC1BEC5A4E00E51F15F6FA70C3871697978916416A1")

    @Test
    fun cfbDecryptWithKnownSessionKey() {
        val enc = resource("fixture-enc.gpg")
        val msg = com.offlinepass.app.vault.PgpMessageParser.parse(enc)
        // The SEIPD body decrypts with the known session key.
        val plain = OpenPgpSeipd.decrypt(msg.seipdBody!!, knownSessionKey, 9)
        val expected = resource("fixture-plain.txt")
        assertEquals(String(expected), String(plain))
    }

    @Test
    fun decryptsRealGpgFixtureToOriginalPlaintext() {
        val enc = resource("fixture-enc.gpg")
        val msg = com.offlinepass.app.vault.PgpMessageParser.parse(enc)
        val pkesk = msg.pkesks.single()
        val mpiValue = pkesk.encryptedSessionKey.copyOfRange(2, pkesk.encryptedSessionKey.size)
        val block = cardDecrypt(mpiValue)
        val (algo, sessionKey) = com.offlinepass.app.vault.PgpMessageParser
            .sessionKeyFromPkeskValue(OpenPgpSeipd.stripType2(block))
        // The session key must match the known one.
        org.junit.Assert.assertArrayEquals(knownSessionKey, sessionKey)
        val plain = OpenPgpSeipd.decrypt(msg.seipdBody!!, sessionKey, algo)
        val expected = resource("fixture-plain.txt")
        assertEquals(String(expected), String(plain))
    }

    @Test
    fun myCfbMatchesBouncyCastleOpenPgpCfb() {
        val msg = com.offlinepass.app.vault.PgpMessageParser.parse(resource("fixture-enc.gpg"))
        val body = msg.seipdBody!!
        val sessionKey = ByteArray(32) { (it * 3 + 1).toByte() } // any key; BOTH must agree
        // MY CFB:
        val mine = OpenPgpSeipd.decryptForCompare(body, sessionKey, msg.seipdAlgo!!)
        // BC's OpenPGPCFB:
        val cfb = org.bouncycastle.crypto.modes.OpenPGPCFBBlockCipher(
            org.bouncycastle.crypto.engines.AESEngine())
        cfb.init(false, org.bouncycastle.crypto.params.KeyParameter(sessionKey))
        val bcOut = ByteArray(body.size)
        var inOff = 0; var outOff = 0
        val bs = cfb.blockSize
        while (inOff < body.size) {
            val chunk = minOf(bs, body.size - inOff)
            val block = body.copyOfRange(inOff, inOff + chunk)
            val padded = if (chunk < bs) block + ByteArray(bs - chunk) else block
            val processed = ByteArray(bs)
            val n = cfb.processBlock(padded, 0, processed, 0)
            processed.copyInto(bcOut, outOff, 0, chunk)
            inOff += chunk; outOff += chunk
        }
        println("DBG mine  =" + mine.take(24).joinToString(" ") { "%02x".format(it) })
        println("DBG bc    =" + bcOut.take(24).joinToString(" ") { "%02x".format(it) })
        assertTrue("my CFB must match BC's OpenPGPCFB",
            mine.contentEquals(bcOut))
    }

    @Test
    fun tamperedCiphertextFailsMdc() {
        val enc = resource("fixture-enc.gpg").copyOf()
        enc[enc.size - 5] = (enc[enc.size - 5].toInt() xor 1).toByte()
        val msg = com.offlinepass.app.vault.PgpMessageParser.parse(enc)
        val pkesk = msg.pkesks.single()
        val mpiValue = pkesk.encryptedSessionKey.copyOfRange(2, pkesk.encryptedSessionKey.size)
        val block = cardDecrypt(mpiValue)
        val (algo, sessionKey) = com.offlinepass.app.vault.PgpMessageParser
            .sessionKeyFromPkeskValue(OpenPgpSeipd.stripType2(block))
        val ex = runCatching { OpenPgpSeipd.decrypt(msg.seipdBody!!, sessionKey, algo) }
        assertTrue("the tampered body must fail (the MDC)", ex.isFailure)
    }
}
