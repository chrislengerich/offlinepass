package com.offlinepass.app.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.util.Base64

/**
 * The SSH auth self-test's VERDICT logic (JVM): a fake OpenPgpOps feeds
 * hand-built OpenPGP signature armor (the same builders as
 * PgpSshBridgeTest) through sshAuthSelfTest and asserts the verdict for
 * the error / wrong-key / happy paths. The real OpenKeyChain interaction
 * is device-side (the connectedDebugAndroidTest covers it semi-manually).
 */
@RunWith(RobolectricTestRunner::class)
class SshSelfTestLogicTest {

    private val SUBKEY_ID = java.lang.Long.parseUnsignedLong("C8F4AEE13C3FA96E", 16)

    // -- packet builders (mirror PgpSshBridgeTest) -----------------------------

    private fun u16(v: Int) = byteArrayOf(((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    private fun mpi(value: ByteArray): ByteArray {
        var v = value
        while (v.size > 1 && v[0] == 0x00.toByte()) v = v.copyOfRange(1, v.size)
        val bits = java.math.BigInteger(1, v).bitLength()
        val len = (bits + 7) / 8
        val content = v.copyOfRange(v.size - len, v.size)
        return byteArrayOf(((bits ushr 8) and 0xFF).toByte(), (bits and 0xFF).toByte()) + content
    }

    /** v4 signature: hashed area (empty), unhashed area carrying an ISSUER
     *  FINGERPRINT subpacket (type 33) naming [keyId], then the RSA sig MPI. */
    private fun armoredSig(keyId: Long): String {
        val issuerFpr = ByteArray(16) + byteArrayOf(
                (keyId ushr 56).toByte(), (keyId ushr 48).toByte(), (keyId ushr 40).toByte(), (keyId ushr 32).toByte(),
                (keyId ushr 24).toByte(), (keyId ushr 16).toByte(), (keyId ushr 8).toByte(), keyId.toByte())
        val issuerSub = byteArrayOf((issuerFpr.size + 1).toByte(), 33) + issuerFpr
        val raw = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val body = byteArrayOf(4, 0, 1, 8) + u16(0) + u16(issuerSub.size) + issuerSub + mpi(raw)
        val packet = byteArrayOf(0xC2.toByte()) + byteArrayOf(body.size.toByte()) + body
        return "-----BEGIN PGP SIGNATURE-----\n" +
            java.util.Base64.getEncoder().encodeToString(packet) +
            "\n-----END PGP SIGNATURE-----\n"
    }

    private fun sshRsaLine(): String = "ssh-rsa " + Base64.getEncoder().encodeToString(
        run {
            val out = java.io.ByteArrayOutputStream()
            fun s(b: ByteArray) {
                val l = b.size
                out.write(byteArrayOf((l ushr 24).toByte(), (l ushr 16).toByte(), (l ushr 8).toByte(), l.toByte()))
                out.write(b)
            }
            s("ssh-rsa".toByteArray())
            s(byteArrayOf(1, 0, 1))                       // e
            s(ByteArray(64) { (it % 7).toByte() })        // n (test size)
            out.toByteArray()
        }) + " test"

    // -- fake client -------------------------------------------------------------

    private class FakeClient(
        private val result: com.offlinepass.app.crypto.OpenPgpClient.SignDetached
    ) : com.offlinepass.app.crypto.OpenPgpOps {
        override suspend fun lookupKeyIds(
            emails: Array<String>, requestData: android.content.Intent?
        ): com.offlinepass.app.crypto.OpenPgpClient.KeyLookup =
            com.offlinepass.app.crypto.OpenPgpClient.KeyLookup.Success(longArrayOf())
        override suspend fun encryptTo(
            keyIds: LongArray, source: File, target: File
        ): Boolean = false
        override suspend fun fetchPublicKeyArmored(
            keyId: Long, requestData: android.content.Intent?
        ): com.offlinepass.app.crypto.OpenPgpClient.PublicKey =
            com.offlinepass.app.crypto.OpenPgpClient.PublicKey.Error
        override suspend fun trySignDetached(
            data: ByteArray, keyId: Long?, requestData: android.content.Intent?, apiVersion: Int
        ): com.offlinepass.app.crypto.OpenPgpClient.SignDetached = result
        override suspend fun pickSignKey(
            requestData: android.content.Intent?
        ): com.offlinepass.app.crypto.OpenPgpClient.SignKey =
            com.offlinepass.app.crypto.OpenPgpClient.SignKey.Error
    }

    @Before
    fun setup() {
        VaultSession.resetForTest(RuntimeEnvironment.getApplication())
        VaultSession.setYubikeySsh(sshRsaLine(), "C8F4AEE13C3FA96E")
        VaultSession.openPgpClientFactory = { FakeClient(fakeResult) }
    }

    private var fakeResult: com.offlinepass.app.crypto.OpenPgpClient.SignDetached =
        com.offlinepass.app.crypto.OpenPgpClient.SignDetached.Error("not set")

    @Test
    fun errorNamesTheOkkMessage() = kotlinx.coroutines.runBlocking {
        fakeResult = com.offlinepass.app.crypto.OpenPgpClient.SignDetached.Error("key not allowed")
        val v = VaultSession.sshAuthSelfTest()
        assertFalse(v.ok)
        assertTrue(v.detail.contains("key not allowed"))
    }

    @Test
    fun okWithMatchingIssuerPassesTheBridge() = kotlinx.coroutines.runBlocking {
        fakeResult = com.offlinepass.app.crypto.OpenPgpClient.SignDetached.Ok(armoredSig(SUBKEY_ID))
        val v = VaultSession.sshAuthSelfTest()
        assertTrue("verdict: " + v.detail, v.ok)
        assertTrue(v.detail.contains("SSH framing OK"))
    }

    @Test
    fun wrongIssuerFailsTheVerdict() = kotlinx.coroutines.runBlocking {
        fakeResult = com.offlinepass.app.crypto.OpenPgpClient.SignDetached.Ok(armoredSig(0x12345678L))
        val v = VaultSession.sshAuthSelfTest()
        assertFalse(v.ok)
        assertTrue(v.detail.contains("not the enrolled"))
    }
}
