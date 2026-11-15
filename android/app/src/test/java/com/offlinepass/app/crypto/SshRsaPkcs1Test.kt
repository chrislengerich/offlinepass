package com.offlinepass.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/** SshRsaPkcs1: the DigestInfo framing + the PKCS#1 v1.5 padding that the
 *  card's PSO:CDS expects. */
class SshRsaPkcs1Test {

    @Test
    fun digestInfoMatchesRfc8017Form() {
        // The known SHA-256 DigestInfo of the empty message.
        val block = SshRsaPkcs1.pkcs1SignBlock("SHA-256", ByteArray(0), 128)
        assertEquals(128, block.size)
        assertEquals(0x00.toByte(), block[0])
        assertEquals(0x01.toByte(), block[1])
        assertEquals(0xFF.toByte(), block[2])
        // the DI starts after the 00 terminator: 3 + 74 pad = 77
        assertEquals(0x00.toByte(), block[76])
        val di = block.copyOfRange(77, 128)
        assertEquals(51, di.size)
        val expected = byteArrayOf(
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01,
            0x65.toByte(), 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20.toByte())
        assertArrayEquals(expected, di.copyOfRange(0, expected.size))
        // the SHA-256 of "" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assertEquals(0xe3.toByte(), di[19])
        assertEquals(0xb0.toByte(), di[20])
    }

    @Test
    fun sha512BlockPadsToModulusSize() {
        val block = SshRsaPkcs1.pkcs1SignBlock("SHA-512", byteArrayOf(1, 2, 3), 512)
        assertEquals(512, block.size)
        assertEquals(0x01.toByte(), block[1])
        // the SHA-512 DI = 19 + 64 = 83 bytes; the 0x40 = the DI's index 18
        assertEquals(0x40.toByte(), block[512 - 83 + 18])
    }
}
