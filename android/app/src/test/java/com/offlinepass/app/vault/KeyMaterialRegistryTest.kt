package com.offlinepass.app.vault

import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

/**
 * The repo's key-material registry (meta/devices.json + the keys/{auth,
 * sign,encrypt} folders) without hardware: the LEGACY flat layout
 * migrates once (the files move, meta is created); device-tagged entries
 * are append-only (a second device appends, never overwrites); the
 * un-enroll migration is surgical (only the local device's entry is
 * removed).
 */
@RunWith(RobolectricTestRunner::class)
class KeyMaterialRegistryTest {

    @Before
    fun setUp() {
        VaultSession.resetForTest(RuntimeEnvironment.getApplication() as Context)
    }

    private fun repoRoot(): File = File(VaultSession.gitRootPath())

    private fun legacyMaterial() {
        val keys = File(repoRoot(), "keys").apply { mkdirs() }
        File(keys, "63EBEE3E00698013.public.asc").writeText("-----BEGIN PGP PUBLIC KEY BLOCK-----\nrec\n")
        File(keys, "signer-63EBEE3E00698013.asc").writeText("-----BEGIN PGP PUBLIC KEY BLOCK-----\ncard\n")
        File(keys, "keystore-signer.pub").writeText("-----BEGIN PUBLIC KEY-----\nlegacy-pem\n")
        File(keys, "recipients.txt").writeText("ledger\n")
    }

    @Test
    fun legacyLayoutMigratesOnceIntoSubfoldersAndMeta() {
        legacyMaterial()

        VaultSession.migrateLegacyKeyLayoutForTest()

        // The files MOVED into their role folders.
        assertTrue(File(repoRoot(), "keys/encrypt/63EBEE3E00698013.pub.asc").exists())
        assertTrue(File(repoRoot(), "keys/sign/63EBEE3E00698013.pub.asc").exists())
        assertTrue(File(repoRoot(), "keys/sign/keystore-signer.pub").exists())
        assertTrue(File(repoRoot(), "keys/encrypt/recipients.txt").exists())
        // The legacy originals are gone (git history preserves them).
        assertFalse(File(repoRoot(), "keys/63EBEE3E00698013.public.asc").exists())
        assertFalse(File(repoRoot(), "keys/keystore-signer.pub").exists())

        // The second run is a no-op (no duplication, no crash).
        VaultSession.migrateLegacyKeyLayoutForTest()
        assertTrue(File(repoRoot(), "keys/encrypt/63EBEE3E00698013.pub.asc").exists())
    }

    @Test
    fun metaRoundTripAndLookup() {
        VaultSession.setDeviceName("Pixel 8")
        VaultSession.writeDeviceRegistryForTest(listOf(
            VaultSession.DeviceRegistryEntry(
                "Pixel 8",
                "ecdsa-sha2-nistp256 AAAA1 offlinepass-screenlock device=d1", null),
            VaultSession.DeviceRegistryEntry(
                "Pixel 8 (card)",
                "ssh-rsa AAAA2 offlinepass-yubikey",
                "keys/sign/63EBEE3E00698013.pub.asc")))

        val entries = VaultSession.readDeviceRegistry()
        assertEquals(2, entries.size)
        assertEquals("Pixel 8", entries[0].name)
        assertEquals("keys/sign/63EBEE3E00698013.pub.asc", entries[1].cert)

        // The lookup rides on the key line's own device comment.
        VaultSession.setDeviceName("Pixel 8") // does not affect the match
        assertFalse(VaultSession.screenlockRegisteredForThisDevice())
    }

    @Test
    fun migrationRemovesOnlyThisDevicesMetaEntryAndAuthLine() {
        val f = File(repoRoot(), "keys/auth/authorized-keys")
        f.parentFile.mkdirs()
        f.writeText(
            "ecdsa-sha2-nistp256 AAAAother offlinepass-screenlock device=other-device\n" +
            "ssh-rsa AAAAcard offlinepass-yubikey\n")

        VaultSession.writeDeviceRegistryForTest(listOf(
            VaultSession.DeviceRegistryEntry(
                "Other",
                "ecdsa-sha2-nistp256 AAAAother offlinepass-screenlock device=other-device", null),
            VaultSession.DeviceRegistryEntry(
                "This",
                "ecdsa-sha2-nistp256 AAAAmine offlinepass-screenlock " +
                    "device=" + VaultSession.deviceId(), null),
            VaultSession.DeviceRegistryEntry(
                "This (card)", "ssh-rsa AAAAcard offlinepass-yubikey", null)))

        VaultSession.migrateOffScreenlock()

        // meta: this device's screenlock entry GONE; the other device's AND
        // the card's survive.
        val entries = VaultSession.readDeviceRegistry()
        assertEquals(2, entries.size)
        assertTrue(entries.any { it.name == "Other" })
        assertTrue(entries.any { it.name == "This (card)" })

        // The transport registry: this device's screenlock line gone; the
        // card's line survives.
        val auth = File(repoRoot(), "keys/auth/authorized-keys").readText()
        assertFalse(auth.contains("device=" + VaultSession.deviceId()))
        assertTrue(auth.contains("offlinepass-yubikey"))
        assertTrue(auth.contains("other-device"))
    }

    // -- The authorized-keys dedupe keys on the BLOB --------------------------

    @Test
    fun twoDifferentRsaLinesBothAppend() {
        // The dedupe must key on the base64 BLOB — the alg token collapsed
        // every ssh-rsa line into one (the second device's card line never
        // registered).
        VaultSession.updateAuthorizedKeysForTest(listOf(
            "ssh-rsa AAAAone offlinepass-yubikey",
            "ssh-rsa AAAAtwo offlinepass-card2"))
        val f = File(repoRoot(), "keys/auth/authorized-keys")
        assertEquals(2, f.readLines().filter { it.isNotBlank() }.size)
        // Re-adding the SAME blob stays deduped.
        VaultSession.updateAuthorizedKeysForTest(listOf(
            "ssh-rsa AAAAone offlinepass-yubikey"))
        assertEquals(2, f.readLines().filter { it.isNotBlank() }.size)
    }

    @Test
    fun okkHandoffStagesOneOverwrittenFile() {
        val signDir = File(repoRoot(), "keys/sign").apply { mkdirs() }
        File(signDir, "63EBEE3E00698013.pub.asc")
            .writeText("-----BEGIN PGP PUBLIC KEY BLOCK-----\ncard\n")
        val files = VaultSession.repoKeyMaterialFiles()
        assertEquals(1, files.size)
        assertTrue(files[0].name.endsWith(".pub.asc"))
    }
    @Test
    fun deviceListLabelsCarryNameKindAndThisDeviceMarker() {
        val mine = VaultSession.deviceId()
        VaultSession.writeDeviceRegistryForTest(listOf(
            VaultSession.DeviceRegistryEntry(
                "Pixel 8", "ecdsa-sha2-nistp256 AAAA1 offlinepass-screenlock " +
                    "device=$mine", null),
            VaultSession.DeviceRegistryEntry(
                "Laptop", "ecdsa-sha2-nistp256 AAAA2 offlinepass-screenlock " +
                    "device=laptop-id", null),
            VaultSession.DeviceRegistryEntry(
                "Pixel 8 (card)", "ssh-rsa AAAAcard offlinepass-yubikey",
                "keys/sign/63EBEE3E00698013.pub.asc")))

        val labels = VaultSession.deviceListLabels()

        assertEquals(3, labels.size)
        assertTrue(labels[0].contains("Pixel 8 — screenlock (sign) — this device"))
        assertTrue(labels[1].contains("Laptop — screenlock (sign)") &&
            !labels[1].contains("this device"))
        assertTrue(labels[2].contains("security key (auth + sign)"))
    }

    // -- The signing protocol (the enrollment order + the revocation) -------

    @Test
    fun revocationViaRepoFlipsLocalSignerToSecurityKey() {
        // Another device's security-key-signed commit removed THIS device's
        // screenlock entry from the registry. The local mode still says
        // screenlock — the reconciliation must honor the revocation.
        enrollLikeThisDevice()
        VaultSession.setCommitSigningMode(VaultSession.SIGNING_SCREENLOCK)
        // The registry: only ANOTHER device's entry (this device's was
        // removed remotely).
        VaultSession.writeDeviceRegistryForTest(listOf(
            VaultSession.DeviceRegistryEntry(
                "Laptop", "ecdsa-sha2-nistp256 AAAA2 offlinepass-screenlock " +
                    "device=laptop-id", null)))

        VaultSession.reconcileSignersAfterSync()

        assertEquals(VaultSession.SIGNING_YUBIKEY, VaultSession.commitSigningMode())
    }

    @Test
    fun reconciliationIsANoOpWhenStillRegistered() {
        enrollLikeThisDevice()
        VaultSession.setCommitSigningMode(VaultSession.SIGNING_SCREENLOCK)
        VaultSession.writeDeviceRegistryForTest(listOf(
            VaultSession.DeviceRegistryEntry(
                "This", "ecdsa-sha2-nistp256 AAAAmine offlinepass-screenlock " +
                    "device=" + VaultSession.deviceId(), null)))
        println("DBG deviceId=" + VaultSession.deviceId())
        println("DBG entries=" + VaultSession.readDeviceRegistry())
        VaultSession.reconcileSignersAfterSync()
        println("DBG mode=" + VaultSession.commitSigningMode())
        assertEquals(VaultSession.SIGNING_SCREENLOCK, VaultSession.commitSigningMode())
    }

    private fun enrollLikeThisDevice() {
        VaultSession.setYubikeySsh(
            "ssh-rsa AAAAB3test offlinepass-test", "63EBEE3E00698013")
    }

}
