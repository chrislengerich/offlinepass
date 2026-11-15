package com.offlinepass.app.vault

import android.content.Context
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

/**
 * buildSshIdentity's YubiKey mode without hardware: the YubiKit card path
 * is the ONLY backend. No enrollment → plain null; enrolled but the key
 * detached → fail-fast with a NAMED message (the OKK card-sign dead end
 * must never be silently re-entered). The attached+permitted branch is a
 * thin UsbManager check verified on-device; its identity construction is
 * covered by YubiKeySshIdentityTest.
 */
@RunWith(RobolectricTestRunner::class)
class SshIdentityProviderTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        VaultSession.resetForTest(context)
    }

    @Test
    fun yubikeyModeWithoutEnrollmentBuildsNothing() {
        VaultSession.setSshSyncMode(VaultSession.SSH_SYNC_YUBIKEY)
        assertNull(VaultSession.buildSshIdentity())
        assertNull(VaultSession.sshIdentityUnavailable)
    }

    @Test
    fun enrolledButDetachedFailsFastWithANamedMessage() {
        // Enrollment (also switches the mode to YUBIKEY); the canonical
        // ssh-rsa line: RSA 2048, mpint sign byte included.
        val kp = java.security.KeyPairGenerator.getInstance("RSA")
            .apply { initialize(2048) }.generateKeyPair()
        val pub = kp.public as java.security.interfaces.RSAPublicKey
        val e = pub.publicExponent.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        val n = pub.modulus.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        fun mpint(v: ByteArray) = if ((v[0].toInt() and 0x80) != 0) byteArrayOf(0) + v else v
        fun sshString(b: ByteArray): ByteArray {
            val out = ByteArray(4 + b.size)
            out[0] = ((b.size ushr 24) and 0xFF).toByte()
            out[1] = ((b.size ushr 16) and 0xFF).toByte()
            out[2] = ((b.size ushr 8) and 0xFF).toByte()
            out[3] = (b.size and 0xFF).toByte()
            b.copyInto(out, 4)
            return out
        }
        val blob = sshString("ssh-rsa".toByteArray()) + sshString(mpint(e)) + sshString(mpint(n))
        VaultSession.setYubikeySsh(
            "ssh-rsa " + java.util.Base64.getEncoder().encodeToString(blob) + " test",
            "63EBEE3E00698013")

        // No YubiKey in Robolectric's UsbManager → deviceReady=false.
        assertNull(VaultSession.buildSshIdentity())
        assertTrue(
            "the unavailability message must name the YubiKey: " +
                VaultSession.sshIdentityUnavailable,
            VaultSession.sshIdentityUnavailable?.contains("YubiKey") == true)
    }
}
