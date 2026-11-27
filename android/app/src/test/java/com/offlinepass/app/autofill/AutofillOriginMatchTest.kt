package com.offlinepass.app.autofill

import com.offlinepass.app.vault.ProtonItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * THE ORIGIN MATCHER's contract — the precise URL→item rule the fill
 * sheet ranks by. The old `contains()` substring matched `xicml.cc` for
 * the domain `icml.cc` (no dot boundary) and offered the browser-package
 * check as a matcher (no URL contains `com.android.chrome`) — both dead.
 */
@RunWith(RobolectricTestRunner::class)
class AutofillOriginMatchTest {

    // -- hostOf ---------------------------------------------------------------

    @Test
    fun hostOfParsesSchemedAndBare() {
        assertEquals("example.com", OriginMatch.hostOf("https://example.com/login"))
        assertEquals("example.com", OriginMatch.hostOf("example.com/login"))
        assertEquals("example.com", OriginMatch.hostOf("https://www.Example.com"))
        assertNull(OriginMatch.hostOf("not a url"))
    }

    // -- hostMatches: the dot boundary is the whole point ---------------------

    @Test
    fun exactAndSubdomainMatch() {
        assertTrue(OriginMatch.hostMatches("icml.cc", "icml.cc"))
        assertTrue(OriginMatch.hostMatches("login.icml.cc", "icml.cc"))
        assertTrue(OriginMatch.hostMatches("icml.cc", "login.icml.cc"))
    }

    @Test
    fun theSuffixTrapDoesNotMatch() {
        // THE MEASURED FALSE-POSITIVE: contains() said yes.
        assertFalse(OriginMatch.hostMatches("xicml.cc", "icml.cc"))
        assertFalse(OriginMatch.hostMatches("notgmail.com", "gmail.com"))
        assertFalse(OriginMatch.hostMatches("evil-gmail.com", "gmail.com"))
    }

    // -- packageMatches: the reverse-domain convention ------------------------

    @Test
    fun nativeAppReverseDomainMatches() {
        assertTrue(OriginMatch.packageMatches("bank.com", "com.bank.app"))
        assertTrue(OriginMatch.packageMatches("proton.me", "me.proton.android.pass"))
        assertTrue(OriginMatch.packageMatches("bank.com", "com.bank"))
    }

    @Test
    fun nativeAppDotBoundaryGuard() {
        // com.banky.app must NOT match bank.com — the '.' at the boundary.
        assertFalse(OriginMatch.packageMatches("bank.com", "com.banky.app"))
        // AND the browser's package never matches any site (the dead-weight
        // check the old contains() carried).
        assertFalse(OriginMatch.packageMatches("icml.cc", "com.android.chrome"))
    }

    // -- rank: the tiers ------------------------------------------------------

    private fun item(vararg urls: String) = ProtonItem(name = "t", urls = urls.toList())

    @Test
    fun domainBeatsPackageBeatsNone() {
        assertEquals(2, OriginMatch.rank(item("https://icml.cc/x"), "icml.cc", "com.android.chrome"))
        assertEquals(1, OriginMatch.rank(item("https://bank.com"), null, "com.bank.app"))
        assertEquals(0, OriginMatch.rank(item("https://other.org"), "icml.cc", "com.android.chrome"))
    }

    @Test
    fun matchesPredicateUsesThePreciseRule() {
        val f = OfflinepassAutofillService.Fields(
            username = emptyList(), email = emptyList(), password = emptyList(),
            appPackage = "com.android.chrome", webDomain = "icml.cc")
        assertTrue(f.matches(item("https://2017.icml.cc/Profile")))
        assertFalse(f.matches(item("https://xicml.cc/")))
        assertFalse(f.matches(item()))
    }
}
