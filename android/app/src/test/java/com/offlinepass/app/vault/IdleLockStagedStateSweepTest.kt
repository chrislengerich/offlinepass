package com.offlinepass.app.vault

import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

/**
 * THE ZERO→UNLOCK SWEEP (work-plan T4): the idle lock's zero() must not
 * eat ANY stage-able state. The paste-stash regression (2d05cc9) was one
 * instance of the class; this suite pins the whole loop per state type:
 * zero() → (the stash) → promoteSealedSession() → save() → persisted.
 */
@RunWith(RobolectricTestRunner::class)
class IdleLockStagedStateSweepTest {

    @Before
    fun setUp() {
        VaultSession.resetForTest(RuntimeEnvironment.getApplication() as Context)
        SealedVault.resetForTest(RuntimeEnvironment.getApplication() as Context)
        // The seal crypto = the software fake (no keystore under Robolectric).
        SealedVault.cryptoHook = object : SealedVault.SealCrypto {
            private val key = javax.crypto.spec.SecretKeySpec(
                ByteArray(32) { (it * 3 + 5).toByte() }, "AES")
            override fun seal(plain: ByteArray, aad: ByteArray): Pair<ByteArray, ByteArray> {
                val iv = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
                val c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
                c.init(javax.crypto.Cipher.ENCRYPT_MODE, key,
                    javax.crypto.spec.GCMParameterSpec(128, iv))
                c.updateAAD(aad)
                return iv to c.doFinal(plain)
            }
            override fun unseal(iv: ByteArray, ct: ByteArray, aad: ByteArray): ByteArray {
                val c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
                c.init(javax.crypto.Cipher.DECRYPT_MODE, key,
                    javax.crypto.spec.GCMParameterSpec(128, iv))
                c.updateAAD(aad)
                return c.doFinal(ct)
            }
        }
        VaultSession.vaultEncryptBytes = { plain, _, _ ->
            java.util.Base64.getEncoder().encode(plain)
        }
        VaultSession.vaultDecryptBytes = { bytes ->
            java.util.Base64.getDecoder().decode(bytes)
        }
    }

    private fun vaultFile() = File(VaultSession.vaultFilePath())

    /** The stub session + the sealed cache with two items (rev 3) — the
     *  unlocked-session shape (the same fixture PasteDeviceStagingTest
     *  uses). */
    private fun seedStubSession() {
        VaultSession.configure(null, emptyList())
        VaultSession.setRecipientKeyIds(listOf(12345L))
        val encDir = File(VaultSession.gitRootPath(), "keys/encrypt")
        encDir.mkdirs()
        File(encDir, "%016X.pub.asc".format(12345L)).writeText("the test key")
        kotlinx.coroutines.runBlocking { VaultSession.setScreenlockUnlockEnabled(true) }
        val items = listOf(
            ProtonItem(name = "A", username = "ua", password = "pa", itemUuid = "u-a"),
            ProtonItem(name = "B", username = "ub", password = "pb", itemUuid = "u-b"))
        val env = Envelope(rev = 3, deviceId = "d1")
        env.items = items.toMutableList()
        val vf = vaultFile()
        vf.parentFile?.mkdirs()
        vf.writeText("ciphertext-blob-v1")
        kotlinx.coroutines.runBlocking {
            SealedVault.sealNowAwait(items, env, vf)
        }
        VaultSession.stubSessionForTest()
        assertTrue(SealedVault.hasCache())
    }

    private fun deviceRecord(keyId: String, name: String): DeviceRecord =
        DeviceRecord.fromJson(org.json.JSONObject("""{"id":"$keyId","name":"$name",
            "credId":"cred-$keyId","pub":"pub-$keyId",
            "keyId":"$keyId","added":1,"salt":"s",
            "wrapped":{"iv":"i","ct":"c"}}"""))!!

    private fun unlock(): VaultSession.State.Unlocked {
        val r = kotlinx.coroutines.runBlocking { VaultSession.promoteSealedSession() }
        assertTrue("the promote succeeds ($r)", r is VaultSession.Result.Success)
        return VaultSession.state as VaultSession.State.Unlocked
    }

    private fun savePersistedDevices(): List<DeviceRecord> {
        val stubs = (VaultSession.state as VaultSession.State.Unlocked).items
        val r = kotlinx.coroutines.runBlocking { VaultSession.save(stubs) }
        assertTrue("the save succeeds ($r)", r is VaultSession.Result.Success)
        return Envelope.fromJson(String(java.util.Base64.getDecoder()
            .decode(vaultFile().readBytes()))).devices
    }

    @Test
    fun `sweep - a device REMOVAL (unpair) survives zero - promote - save`() {
        seedStubSession()
        VaultSession.stagePairedDevice(deviceRecord("key-a", "CB A"))
        VaultSession.stagePairedDevice(deviceRecord("key-b", "CB B"))
        assertTrue(VaultSession.stageRemoveDevice("key-a"))

        VaultSession.zero()
        val stubs = unlock()
        kotlinx.coroutines.runBlocking { VaultSession.save(stubs.items) }

        val committed = Envelope.fromJson(String(java.util.Base64.getDecoder()
            .decode(vaultFile().readBytes())))
        assertTrue("the removal tombstoned and persisted",
            committed.removedDeviceIds.contains("key-a"))
        assertTrue("the removed record not resurrected",
            committed.devices.none { it.keyId == "key-a" })
        assertTrue("the untouched pairing survives",
            committed.devices.any { it.keyId == "key-b" })
    }

    @Test
    fun `sweep - a DOUBLE zero keeps the stash (the second zero must not overwrite)`() {
        // The real-world path: the idle lock fires zero(), then the
        // activity teardown (onDestroy) fires zero() AGAIN — the second
        // call sees no envelope and must not clobber the first stash.
        seedStubSession()
        VaultSession.stagePairedDevice(deviceRecord("key-d", "Twice CB"))

        VaultSession.zero()
        VaultSession.zero()
        val stubs = unlock()
        kotlinx.coroutines.runBlocking { VaultSession.save(stubs.items) }

        assertTrue("the pairing survived the double zero",
            Envelope.fromJson(String(java.util.Base64.getDecoder()
                .decode(vaultFile().readBytes())))
                .devices.any { it.name == "Twice CB" })
    }

    @Test
    fun `sweep - the promote consumes the stash exactly once (no duplication)`() {
        seedStubSession()
        VaultSession.stagePairedDevice(deviceRecord("key-e", "Once CB"))

        VaultSession.zero()
        unlock()
        // A SECOND promote (the edge: unlock → idle → unlock again) must
        // not re-carry the stashed record (the stash is consumed).
        val stubs = unlock()
        kotlinx.coroutines.runBlocking { VaultSession.save(stubs.items) }

        val committed = Envelope.fromJson(String(java.util.Base64.getDecoder()
            .decode(vaultFile().readBytes())))
        assertEquals("the record appears exactly once",
            1, committed.devices.count { it.name == "Once CB" })
    }

    @Test
    fun `sweep - zero clears the plaintext (items, tombstones) but keeps the cache and the vault file`() {
        seedStubSession()
        VaultSession.zero()
        assertTrue(VaultSession.state is VaultSession.State.Locked)
        assertTrue("the sealed cache survives", SealedVault.hasCache())
        assertTrue("the vault file untouched", vaultFile().exists())

        // The plaintext really is gone: the promote restores from the cache.
        val stubs = unlock()
        assertEquals(2, stubs.items.size)
    }
}
