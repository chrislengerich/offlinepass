package com.offlinepass.app.vault

import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

/**
 * THE PAIRED-BUT-NOT-SHOWING BUG: a paste-device pairing staged in the
 * STUB session lived only in loadedEnvelope.devices — the save's
 * promote rebuilt the envelope from the sealed cache's meta (whose
 * devices snapshot predates the staging) and WIPED it. The promote must
 * carry the staged pairings the same way it carries the tombstones.
 */
@RunWith(RobolectricTestRunner::class)
class PasteDeviceStagingTest {

    @Before
    fun setUp() {
        VaultSession.resetForTest(RuntimeEnvironment.getApplication() as Context)
        SealedVault.resetForTest(RuntimeEnvironment.getApplication() as Context)
        // The seal crypto = the software fake (the Robolectric has no keystore).
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
    }

    private fun vaultFile() = File(VaultSession.vaultFilePath())

    init {
        // The crypto seams: the base64 passthrough (the reversible — the
        // tests assert the DEVICES in the committed envelope).
        VaultSession.vaultEncryptBytes = { plain, _, _ ->
            java.util.Base64.getEncoder().encode(plain)
        }
        VaultSession.vaultDecryptBytes = { bytes ->
            java.util.Base64.getDecoder().decode(bytes)
        }
    }

    /** The stub session + the sealed cache seeded with TWO items and the
     *  envelope's rev 3 — the unlock's shape. */
    private fun seedStubSession() {
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
            "keyId":"abcd1234","added":1,"salt":"s",
            "wrapped":{"iv":"i","ct":"c"}}"""))!!

    @Test
    fun `pairing staged in the stub session survives the promote`() {
        seedStubSession()
        // The pairing staged from the Setup screen (the unlocked stub session).
        assertEquals("added", VaultSession.stagePairedDevice(
            deviceRecord("extkey1", "Chromebook")))
        assertTrue("staged in the envelope",
            VaultSession.pairedDevices().any { it.name == "Chromebook" })

        // THE SAVE: the promote runs inside — the pairing must survive.
        val items = (VaultSession.state as VaultSession.State.Unlocked).items
        val r = kotlinx.coroutines.runBlocking {
            VaultSession.save(items)
        }
        assertTrue("the save succeeds ($r)", r is VaultSession.Result.Success)
        assertTrue("THE BUG: the pairing wiped by the promote",
            VaultSession.pairedDevices().any { it.name == "Chromebook" })
    }

    @Test
    fun `paired devices persist to the vault file and come back after the reset`() {
        seedStubSession()
        VaultSession.stagePairedDevice(deviceRecord("extkey2", "Second CB"))
        val items = (VaultSession.state as VaultSession.State.Unlocked).items
        kotlinx.coroutines.runBlocking { VaultSession.save(items) }

        // The vault file's envelope carries the devices.
        val text = String(java.util.Base64.getDecoder().decode(vaultFile().readBytes()))
        val env = Envelope.fromJson(text)
        assertTrue("the devices in the committed envelope",
            env.devices.any { it.name == "Second CB" })

        // The app restart: the reset → the unlock path re-adopts from
        // the vault file (the envelope's devices = the source of truth).
        VaultSession.resetForTest(RuntimeEnvironment.getApplication() as Context)
        SealedVault.wipe()
        // The re-adopt = the file's envelope: the direct seam for the test.
        val reenv = Envelope.fromJson(String(java.util.Base64.getDecoder()
            .decode(vaultFile().readBytes())))
        VaultSession.adopt(reenv)
        assertTrue(VaultSession.pairedDevices().any { it.name == "Second CB" })
    }

    @Test
    fun `staging an update replaces the record and survives`() {
        seedStubSession()
        VaultSession.stagePairedDevice(deviceRecord("extkey3", "CB v1"))
        assertEquals("updated", VaultSession.stagePairedDevice(
            deviceRecord("extkey3", "CB v2")))
        val items = (VaultSession.state as VaultSession.State.Unlocked).items
        kotlinx.coroutines.runBlocking { VaultSession.save(items) }
        assertTrue("the updated record survives",
            VaultSession.pairedDevices().any { it.name == "CB v2" } &&
            VaultSession.pairedDevices().none { it.name == "CB v1" })
    }
}
