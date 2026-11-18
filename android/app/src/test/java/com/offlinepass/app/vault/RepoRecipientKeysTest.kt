package com.offlinepass.app.vault

import com.offlinepass.app.crypto.OpenPgpCardCrypto
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
import java.io.File

/**
 * The repo→keys PLUMBING test: the armored recipient files as they exist
 * in keys/encrypt/ (both layouts) load through
 * [VaultSession.loadRecipientKeysFor] and yield keys the BC envelope
 * actually encrypts with — the card decrypt (the software stand-in)
 * round-trips the result. The save tests inject the crypto seam, so
 * without this the file→key wiring would never run on the JVM.
 */
class RepoRecipientKeysTest {

    init {
        java.security.Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
    }

    /** The fixture primary key (RSA-2048, encryption-capable). */
    private val fixtureKeyId = 0x1EA759B8783363D8UL.toLong()

    private fun resource(name: String): ByteArray =
        javaClass.getResourceAsStream("/openpgp/$name")!!.readBytes()

    /** The software "card": the same raw PSO:DEC contract. */
    private val cardDecrypt: suspend (ByteArray) -> ByteArray = { mpiValue ->
        val decoded = PGPUtil.getDecoderStream(resource("fixture-sec.asc").inputStream())
        val ring = PGPObjectFactory(decoded, JcaKeyFingerprintCalculator()).nextObject()
                as PGPSecretKeyRing
        val sk = ring.getSecretKey(fixtureKeyId.toLong())!!
        val privJca = org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter().getPrivateKey(
            sk.extractPrivateKey(
                JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(charArrayOf())))
        val c = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding")
        c.init(javax.crypto.Cipher.DECRYPT_MODE, privJca)
        val padded = ByteArray(256) { 0 }
        mpiValue.copyInto(padded, 256 - mpiValue.size)
        c.doFinal(padded)
    }

    private fun repoWith(layout: (File) -> Unit): File {
        val root: File = java.nio.file.Files.createTempDirectory("op-repo-keys").toFile()
        layout(root)
        return root
    }

    @Test
    fun loadsModernLayoutAndRoundTrips() = runBlocking {
        val root = repoWith { r ->
            File(r, "keys/encrypt").mkdirs()
            File(r, "keys/encrypt/%016X.pub.asc".format(fixtureKeyId))
                .writeBytes(resource("fixture-pub.asc"))
        }
        val keys = VaultSession.loadRecipientKeysFor(root, longArrayOf(fixtureKeyId))
        assertEquals("the armor must yield the encryption key", 1, keys.size)
        val plain = "the plumbing test envelope".toByteArray(Charsets.UTF_8)
        val env = OpenPgpCardCrypto.encryptToBytes(plain, "10.gpg", keys)
        val back = OpenPgpCardCrypto.decrypt(env, longArrayOf(fixtureKeyId), cardDecrypt)
        assertArrayEquals(plain, back)
    }

    @Test
    fun loadsLegacyFlatLayout() = runBlocking {
        val root = repoWith { r ->
            File(r, "keys").mkdirs()
            File(r, "keys/%016X.public.asc".format(fixtureKeyId))
                .writeBytes(resource("fixture-pub.asc"))
        }
        val keys = VaultSession.loadRecipientKeysFor(root, longArrayOf(fixtureKeyId))
        assertEquals("the legacy layout must load", 1, keys.size)
        val plain = "legacy layout envelope".toByteArray(Charsets.UTF_8)
        val env = OpenPgpCardCrypto.encryptToBytes(plain, "10.gpg", keys)
        val back = OpenPgpCardCrypto.decrypt(env, longArrayOf(fixtureKeyId), cardDecrypt)
        assertArrayEquals(plain, back)
    }

    @Test
    fun missingRecipientFileFailsWithClearMessage() = runBlocking {
        val root = repoWith { r -> File(r, "keys/encrypt").mkdirs() }
        val ex = runCatching {
            VaultSession.loadRecipientKeysFor(root, longArrayOf(fixtureKeyId))
        }.exceptionOrNull()
        assertTrue("must fail: $ex", ex != null)
        assertTrue("must name the key: ${ex?.message}",
            ex!!.message!!.contains("0x${fixtureKeyId.toString(16).uppercase()}"))
        assertTrue("must point at keys/encrypt: ${ex?.message}",
            ex.message!!.contains("keys/encrypt"))
    }
}
