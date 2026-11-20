package com.offlinepass.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * THE Ed25519 AUTH PATH (the AUT slot's PSO:INTERNAL AUTHENTICATE):
 * ssh-ed25519 signs the RAW handshake data with PureEdDSA — the
 * OpenPGP hashed-sign path (OpenKeyChain's detached-sign) cannot serve
 * it, so the identity's Ed25519 branch goes YubiKit-direct
 * (session.authenticate) with the raw payload, and emits
 * string("ssh-ed25519") + string(64-byte r||s).
 */
class Ed25519AuthTest {

    private val point = ByteArray(32) { (it * 3).toByte() }

    /** The ssh-ed25519 wire line: string(name) + string(32B point). */
    private fun edLine(): String {
        fun s(b: ByteArray) = run {
            val l = b.size
            byteArrayOf((l ushr 24).toByte(), (l ushr 16).toByte(),
                (l ushr 8).toByte(), l.toByte()) + b
        }
        val blob = s("ssh-ed25519".toByteArray()) + s(point)
        return "ssh-ed25519 " + java.util.Base64.getEncoder()
            .encodeToString(blob) + " test@device"
    }

    @Test
    fun `the card point's fingerprint equals the enrolled line's`() {
        // THE GATE'S EQUIVALENCE: authenticateAut compares the card's raw
        // point fingerprint against the enrolled line's — the two forms
        // must digest identically or every ed25519 sync fails by name.
        val line = edLine()
        assertEquals(
            PgpSshBridge.fingerprintOf(line),
            PgpSshBridge.ed25519SshLineFingerprint(point))
    }

    @Test
    fun `the identity's ed25519 branch signs the RAW data and emits the wire blob`() =
        kotlinx.coroutines.runBlocking {
            val captured = arrayOfNulls<ByteArray>(1)
            val identity = YubiKeySshIdentity(
                client = null, authSubkeyId = 0L, publicKeyLine = edLine(),
                interaction = { null },
                yubiKitSigner = { payload ->
                    captured[0] = payload
                    ByteArray(64) { 7 }   // the fake r||s
                })

            val data = ByteArray(40) { 9 }
            val sig = identity.getSignature(data, "ssh-ed25519")

            assertNotNull("the signature produced", sig)
            // THE PAYLOAD = THE RAW DATA (no DigestInfo — PureEdDSA).
            assertArrayEquals("the card signs the raw handshake data",
                data, captured[0]!!)
            // THE WIRE: string("ssh-ed25519") + string(64-byte r||s).
            fun readS(b: ByteArray, off: Int): Pair<ByteArray, Int> {
                val l = ((b[off].toInt() and 0xFF) shl 24) or
                    ((b[off + 1].toInt() and 0xFF) shl 16) or
                    ((b[off + 2].toInt() and 0xFF) shl 8) or
                    (b[off + 3].toInt() and 0xFF)
                return b.copyOfRange(off + 4, off + 4 + l) to off + 4 + l
            }
            val (alg, p1) = readS(sig!!, 0)
            assertEquals("ssh-ed25519", String(alg))
            val (sigBytes, _) = readS(sig, p1)
            assertEquals(64, sigBytes.size)
            assertArrayEquals(ByteArray(64) { 7 }, sigBytes)
        }

}
