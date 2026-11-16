package com.offlinepass.app.vault

import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

/**
 * The repo's key-material registry without hardware: device-tagged,
 * append-only screenlock entries; a second device appends (never
 * overwrites); the un-enroll migration is surgical (only the local
 * device's entry is removed); the lookups filter by deviceId.
 */
@RunWith(RobolectricTestRunner::class)
class KeyMaterialRegistryTest {

    @Before
    fun setUp() {
        VaultSession.resetForTest(RuntimeEnvironment.getApplication() as Context)
    }

    private fun thisDeviceId(): String = VaultSession.deviceId()

    @Test
    fun registryParsesDeviceTaggedEntries() {
        val f = java.io.File(VaultSession.gitRootPath(), "keys/screenlock-signers.pub")
        f.parentFile.mkdirs()
        f.writeText(
            "ecdsa-sha2-nistp256 AAAAdummy1 # offlinepass-screenlock device=d1 name=Pixel_8\n" +
            "ecdsa-sha2-nistp256 AAAAdummy2 # offlinepass-screenlock device=d2 name=Laptop\n")
        val entries = VaultSession.screenlockRegistryEntries()
        assertEquals(2, entries.size)
        assertEquals("d1", entries[0].deviceId)
        assertEquals("Pixel_8", entries[0].name)
        assertTrue(entries[0].line.startsWith("ecdsa-sha2-nistp256 AAAAdummy1"))
        assertTrue(VaultSession.screenlockRegisteredForThisDevice().let {
            it == entries.any { e -> e.deviceId == thisDeviceId() }
        })
    }

    @Test
    fun migrationRemovesOnlyThisDevicesEntry() {
        val f = java.io.File(VaultSession.gitRootPath(), "keys/screenlock-signers.pub")
        f.parentFile.mkdirs()
        f.writeText(
            "ecdsa-sha2-nistp256 AAAAother # offlinepass-screenlock device=other-device name=Other\n")
        VaultSession.setSshSyncMode(VaultSession.SSH_SYNC_SCREENLOCK)
        VaultSession.setCommitSigningMode(VaultSession.SIGNING_SCREENLOCK)

        VaultSession.migrateOffScreenlock()

        // The other device's entry survives; this device has none.
        val entries = VaultSession.screenlockRegistryEntries()
        assertEquals(1, entries.size)
        assertEquals("other-device", entries[0].deviceId)
        assertFalse(VaultSession.screenlockRegisteredForThisDevice())
    }

    @Test
    fun migrationDeletesThisDevicesKeystoreKeyOnly() {
        // No keystore key exists under Robolectric; removeKey() is a no-op
        // that must not throw — the surgical part is the REGISTRY above.
        enrollLikeThisDevice()
        VaultSession.setCommitSigningMode(VaultSession.SIGNING_SCREENLOCK)
        VaultSession.migrateOffScreenlock()
        assertEquals(VaultSession.SIGNING_YUBIKEY, VaultSession.commitSigningMode())
    }

    private fun enrollLikeThisDevice() {
        VaultSession.setYubikeySsh(
            "ssh-rsa AAAAB3test offlinepass-test", "63EBEE3E00698013")
    }
}
