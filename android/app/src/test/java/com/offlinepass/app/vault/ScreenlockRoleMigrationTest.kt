package com.offlinepass.app.vault

import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

/**
 * The screenlock's role model without hardware: the bootstrap pull is
 * security-key-only, the screenlock is a first-class LOCAL signer once
 * enrolled (post-load), and the un-enroll migration moves auth + signing
 * off the screenlock key (which is then deleted) — the envelope's OpenPGP
 * recipients are untouched. (Robolectric has no AndroidKeyStore, so
 * KeystoreSigner.hasKey() is deterministically false here — the
 * screenlock-enrolled branches of the resolution are on-device checks.)
 */
@RunWith(RobolectricTestRunner::class)
class ScreenlockRoleMigrationTest {

    @Before
    fun setUp() {
        VaultSession.resetForTest(RuntimeEnvironment.getApplication() as Context)
    }

    private fun enrollYubikey() {
        VaultSession.setYubikeySsh(
            "ssh-rsa AAAAB3test offlinepass-test", "63EBEE3E00698013")
    }

    @Test
    fun loadResolutionFallsBackToTheYubikeyWhenNoScreenlockKey() {
        enrollYubikey()
        VaultSession.resolveCommitSigningModeAfterLoad()
        assertEquals(VaultSession.SIGNING_YUBIKEY, VaultSession.commitSigningMode())
    }

    @Test
    fun loadResolutionKeepsTheDefaultWhenNothingIsEnrolled() {
        VaultSession.resolveCommitSigningModeAfterLoad()
        assertEquals(VaultSession.SIGNING_OPENKEYCHAIN, VaultSession.commitSigningMode())
    }

    @Test
    fun migrationMovesAuthAndSigningToTheYubikeyAndDeletesTheKey() {
        enrollYubikey()
        VaultSession.setSshSyncMode(VaultSession.SSH_SYNC_SCREENLOCK)
        VaultSession.setCommitSigningMode(VaultSession.SIGNING_SCREENLOCK)

        val summary = VaultSession.migrateOffScreenlock()

        assertEquals(VaultSession.SSH_SYNC_YUBIKEY, VaultSession.sshSyncMode())
        assertEquals(VaultSession.SIGNING_YUBIKEY, VaultSession.commitSigningMode())
        assertTrue(summary.contains("deleted"))
        assertTrue(summary.contains("YubiKey"))
    }

    @Test
    fun migrationWithoutYubikeyEnrollmentFallsBackToOkkForSigning() {
        VaultSession.setSshSyncMode(VaultSession.SSH_SYNC_SCREENLOCK)
        VaultSession.setCommitSigningMode(VaultSession.SIGNING_SCREENLOCK)

        val summary = VaultSession.migrateOffScreenlock()

        // No YubiKey enrolled: the SSH auth cannot move (explained), the
        // signing falls back to OpenKeyChain.
        assertEquals(VaultSession.SSH_SYNC_SCREENLOCK, VaultSession.sshSyncMode())
        assertEquals(VaultSession.SIGNING_OPENKEYCHAIN, VaultSession.commitSigningMode())
        assertTrue(summary.contains("stays on the screenlock"))
        assertTrue(summary.contains("OpenKeyChain"))
    }
}
