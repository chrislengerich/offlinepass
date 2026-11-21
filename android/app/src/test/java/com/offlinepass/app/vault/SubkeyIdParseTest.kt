package com.offlinepass.app.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * THE UNSIGNED-HEX KEY-ID PARSE (work-plan T4d): the OpenPGP key ids
 * with the high bit set are NEGATIVE as signed Longs — the naive
 * base-10/toLongOrNull(16) parse returns null for exactly the ids real
 * keys have, and the enrollment silently cancelled (the root cause of
 * the measured "Auth cancelled"). [VaultSession.parseSubkeyId16] must
 * accept the full unsigned 64-bit range, 16 hex digits, and nothing
 * else.
 */
class SubkeyIdParseTest {

    @Test
    fun `the high-bit id parses (the unsigned range)`() {
        // The top bit set: the signed Long = negative — still a valid id.
        assertEquals(-1L, VaultSession.parseSubkeyId16("ffffffffffffffff"))
        assertEquals(Long.MIN_VALUE,
            VaultSession.parseSubkeyId16("8000000000000000"))
    }

    @Test
    fun `the low-bit id parses (the positive range)`() {
        assertEquals(0x72dbb7336c767800L,
            VaultSession.parseSubkeyId16("72dbb7336c767800"))
        assertEquals(1L, VaultSession.parseSubkeyId16("0000000000000001"))
    }

    @Test
    fun `the wrong lengths refuse`() {
        assertNull(VaultSession.parseSubkeyId16(null))
        assertNull(VaultSession.parseSubkeyId16(""))
        assertNull(VaultSession.parseSubkeyId16("72dbb7336c7678"))     // 14
        assertNull(VaultSession.parseSubkeyId16("72dbb7336c76780"))    // 15
        assertNull(VaultSession.parseSubkeyId16("72dbb7336c7678000"))  // 17
        assertNull(VaultSession.parseSubkeyId16("0x72dbb7336c767800")) // the 0x prefix
    }

    @Test
    fun `the non-hex garbage refuses (never a silent zero or a partial)`() {
        assertNull(VaultSession.parseSubkeyId16("72dbb7336c76780g"))
        assertNull(VaultSession.parseSubkeyId16("zzzzzzzzzzzzzzzz"))
        assertNull(VaultSession.parseSubkeyId16("72 dbb7336c76780")) // a space
    }

    @Test
    fun `the upper-case hex parses (the cards report both)`() {
        assertEquals(0x72DBB7336C767800L,
            VaultSession.parseSubkeyId16("72DBB7336C767800"))
    }
}
