package com.offlinepass.app.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Parser fixtures produced by desktop gpg (see test/resources). */
class PgpMessageParserTest {

    @Test
    fun parsesRsaPkesk() {
        val msg = PgpMessageParser.parse(fixture("msg-rsa4096.gpg"))
        val pkesk = msg.pkesks.single()
        assertEquals(3, pkesk.version)
        assertEquals(0xA367234D973E0E3EUL.toLong(), pkesk.keyId)
        assertEquals(1, pkesk.keyAlgorithm) // RSA
        // MPI value: 4096-bit RSA -> 512-byte ciphertext + 2-byte length prefix
        assertEquals(514, pkesk.encryptedSessionKey.size)
        assertNotNull(msg.seipdAlgo)
        assertTrue(msg.seipdBody!!.size > 0)
    }

    @Test
    fun parsesEcdhPkesk() {
        val msg = PgpMessageParser.parse(fixture("msg-rsa.gpg"))
        val pkesk = msg.pkesks.single()
        assertEquals(0xABCACB8D8504CC3CUL.toLong(), pkesk.keyId)
        assertEquals(18, pkesk.keyAlgorithm) // ECDH
        assertTrue(pkesk.encryptedSessionKey.size > 0)
        assertNotNull(msg.seipdAlgo)
        assertNotNull(msg.seipdBody)
    }

    @Test
    fun rejectsNonOpenpgp() {
        val ex = runCatching {
            PgpMessageParser.parse("not an openpgp message".toByteArray())
        }
        assertTrue(ex.isFailure)
    }

    private fun fixture(name: String): ByteArray =
        javaClass.classLoader!!.getResourceAsStream(name)!!.readBytes()
}
