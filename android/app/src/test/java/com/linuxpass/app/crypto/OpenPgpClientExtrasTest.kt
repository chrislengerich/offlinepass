package com.linuxpass.app.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class OpenPgpClientExtrasTest {

    private lateinit var client: OpenPgpClient

    @Before
    fun setup() {
        client = OpenPgpClient(RuntimeEnvironment.getApplication())
    }

    @Test
    fun signatureStatusMapping() {
        assertEquals(OpenPgpClient.Signature.VALID, OpenPgpClient.Signature.fromStatus(2))
        assertEquals(OpenPgpClient.Signature.MISSING_KEY, OpenPgpClient.Signature.fromStatus(4))
        assertEquals(OpenPgpClient.Signature.NO_SIGNATURE, OpenPgpClient.Signature.fromStatus(1))
        assertEquals(OpenPgpClient.Signature.UNKNOWN, OpenPgpClient.Signature.fromStatus(99))
    }

    @Test
    fun shareIntentResolvesNothingWithoutOpenKeychain() {
        // OpenKeychain is not installed on a test device (and never under
        // Robolectric), so the export intent must come back null rather than
        // crash; the settings screen falls back to manual export.
        assertNull(client.publicKeyShareIntent("user@example.com"))
    }
}