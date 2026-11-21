package com.offlinepass.app.vault

import android.content.Context
import com.offlinepass.app.crypto.OpenPgpOps
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

/**
 * THE SIGNER-RESOLUTION MATRIX (work-plan T5): given (the commit-signing
 * mode × the enrollment/hooks state), [VaultSession.syncCommitSigner]
 * must produce the right signer — or null for the UNSIGNED first commit —
 * and never cross the modes. Pins the fallback chain
 * (458bd74/f22d6ab/47c425c) against regressions.
 */
@RunWith(RobolectricTestRunner::class)
class SignerResolutionMatrixTest {

    @Before
    fun setUp() {
        VaultSession.resetForTest(RuntimeEnvironment.getApplication() as Context)
        VaultSession.keystoreSignerHook = null
    }

    private fun okkClient(): OpenPgpOps =
        org.mockito.kotlin.mock()

    private fun setMode(mode: String) = VaultSession.setCommitSigningMode(mode)

    @Test
    fun `screenlock mode + the signer hook - the keystore signer`() {
        setMode(VaultSession.SIGNING_SCREENLOCK)
        VaultSession.keystoreSignerHook = { null }
        val s = VaultSession.syncCommitSigner(okkClient())
        assertTrue("got ${s?.javaClass?.simpleName}",
            s is com.offlinepass.app.crypto.KeystoreCommitSigner)
    }

    @Test
    fun `screenlock mode without the hook - null (the UI layer absent = nothing signs)`() {
        // The hook is only installed by an activity (prepare → the CryptoObject
        // prompt); without it the save must fail honestly, not sign unsigned.
        setMode(VaultSession.SIGNING_SCREENLOCK)
        assertNull(VaultSession.syncCommitSigner(okkClient()))
    }

    @Test
    fun `yubikey mode without a card (no device) - null + the named reason`() {
        setMode(VaultSession.SIGNING_YUBIKEY)
        // Robolectric's UsbManager enumerates no YubiKey → deviceReady false.
        assertNull(VaultSession.yubikeyCommitSignerOrNull())
        assertTrue("the unavailability is NAMED, not silent",
            !VaultSession.sshIdentityUnavailable.isNullOrEmpty())
    }

    @Test
    fun `openkeychain mode + a configured sign key - the OKK signer`() {
        setMode(VaultSession.SIGNING_OPENKEYCHAIN)
        VaultSession.signingKeyForTest(123456789L)
        val s = VaultSession.syncCommitSigner(okkClient())
        assertTrue("got ${s?.javaClass?.simpleName}",
            s is OpenKeyChainSigner)
    }

    @Test
    fun `openkeychain mode with NO sign key - null = the UNSIGNED first commit`() {
        // 47c425c: OpenKeyChain must not gate the first save — no sign key
        // configured = an unsigned commit, never a hard failure.
        setMode(VaultSession.SIGNING_OPENKEYCHAIN)
        assertNull(VaultSession.syncCommitSigner(okkClient()))
    }

    @Test
    fun `the modes are exclusive - the screenlock signer only in screenlock mode`() {
        // The hook present but the mode = OKK: the keystore signer must
        // NOT leak into the OpenKeyChain mode.
        setMode(VaultSession.SIGNING_OPENKEYCHAIN)
        VaultSession.keystoreSignerHook = { null }
        assertNull("no sign key → unsigned (the hook is not a fallback here)",
            VaultSession.syncCommitSigner(okkClient()))
    }

    @Test
    fun `yubikey enrollment resolves the mode after a load (the migration)`() {
        // A vault whose signing mode = SCREENLOCK gaining a YubiKey
        // enrollment → the load's resolve migrates the mode (the
        // screenlock is no longer the auth key).
        setMode(VaultSession.SIGNING_SCREENLOCK)
        VaultSession.setYubikeySsh(
            "ssh-rsa AAAAline offlinepass-yubikey", "72dbb7336c767800")
        VaultSession.resolveCommitSigningModeAfterLoad()
        assertTrue(VaultSession.commitSigningMode() == VaultSession.SIGNING_YUBIKEY)
    }
}
