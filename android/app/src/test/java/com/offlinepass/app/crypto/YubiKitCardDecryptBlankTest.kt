package com.offlinepass.app.crypto

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * THE BLANK-CARD DETECTION: the DEC-slot fingerprint's blank shapes —
 * the spec's 20-zero-bytes DO (the factory-new card) and the absent DO —
 * must read as "no GPG key set" (the README-pointer message), while a
 * real fingerprint (any nonzero byte) reads as enrolled. This closed a
 * real hole: the all-zero fingerprint PASSED the old size-only guard and
 * would have enrolled recipient id 0.
 */
class YubiKitCardDecryptBlankTest {

    @Test
    fun `absent fingerprint is blank`() {
        assertTrue(YubiKitCardDecrypt.isBlankFingerprint(null))
    }

    @Test
    fun `short fingerprint is blank`() {
        assertTrue(YubiKitCardDecrypt.isBlankFingerprint(ByteArray(19)))
    }

    @Test
    fun `all-zero fingerprint is blank (the spec's empty-DO shape)`() {
        assertTrue(YubiKitCardDecrypt.isBlankFingerprint(ByteArray(20)))
    }

    @Test
    fun `a real fingerprint is NOT blank (any nonzero byte)`() {
        val fp = ByteArray(20) // zeros…
        fp[7] = 0x2A           // …but one byte set
        assertFalse(YubiKitCardDecrypt.isBlankFingerprint(fp))
    }

    @Test
    fun `the message names the README sections (the user-facing pointer)`() {
        assertTrue(YubiKitCardDecrypt.BLANK_CARD_MESSAGE
            .contains("no GPG key set (it may have other keys)"))
        assertTrue(YubiKitCardDecrypt.BLANK_CARD_MESSAGE
            .contains("Initialize the security key (OpenPGP key set)"))
        assertTrue(YubiKitCardDecrypt.BLANK_CARD_MESSAGE
            .contains("From Linux (gpg"))
        assertTrue(YubiKitCardDecrypt.BLANK_CARD_MESSAGE
            .contains("From Android (OpenKeyChain"))
        // The README headings exist (the message points at real text).
        assertTrue(YubiKitCardDecrypt.BLANK_CARD_MESSAGE
            .contains("the authoritative flow)"))
        assertTrue(YubiKitCardDecrypt.BLANK_CARD_MESSAGE
            .contains("NFC/USB)"))
    }
}
