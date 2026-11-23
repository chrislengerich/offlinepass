package com.offlinepass.app.autofill

import android.view.autofill.AutofillId
import com.offlinepass.app.vault.ProtonItem
import com.offlinepass.app.vault.SealedVault
import com.offlinepass.app.vault.VaultSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

/**
 * THE CHIP-OFFER CONDITIONS (the on-device failure mode "the ✨ chip
 * never appears" was decided here, untested — the offer decisions and
 * the sealed-manifest SL detection are pinned now): the page-match
 * predicate, the ⚡/✨ offer conditions, and the sealed manifest's SL
 * uuid scan.
 */
@RunWith(RobolectricTestRunner::class)
class ChipOfferConditionsTest {

    private val app = RuntimeEnvironment.getApplication()

    private val svc = OfflinepassAutofillService()

    /** A fresh AutofillId per call. The constructors are package-private
     *  in Robolectric's android-all, so the reflection seam; the
     *  conditions only test the lists' emptiness anyway. */
    private fun fid(): AutofillId =
        AutofillId::class.java.getDeclaredConstructor().apply { isAccessible = true }
            .newInstance() as AutofillId

    private fun fields(
        usernames: Int = 0, passwords: Int = 0,
        pkg: String = "app.vanadium.browser", domain: String? = null,
    ) = OfflinepassAutofillService.Fields(
        username = List(usernames) { fid() },
        password = List(passwords) { fid() },
        appPackage = pkg, webDomain = domain)

    private fun siteItem(name: String, vararg urls: String) =
        ProtonItem(name = name, username = "user", urls = urls.toList())

    /** The sealed cache needs NO crypto for the manifest scan — the
     *  entries' name/urls are clear text (the blobs matter only for the
     *  reveal), so the test writes the cache JSON directly. */
    private fun writeSealedCache(vararg items: ProtonItem) {
        val arr = items.joinToString(",") { it ->
            val urls = it.urls.joinToString(",") { u -> "\"$u\"" }
            """{"uuid":"${it.itemUuid}","name":"${it.name}","username":"",""" +
                """"email":"","urls":[$urls]}"""
        }
        File(File(app.filesDir, "sealed"), "sealed.json").apply {
            parentFile.mkdirs()
            writeText("""{"v":2,"items":[$arr]}""")
        }
    }

    @Before
    fun setUp() {
        // resetForTest (NOT init): the singleton outlives Robolectric's
        // per-test applications — init would early-return and leave the
        // cacheFile pointed at a dead app's filesDir (the measured
        // empty-manifest scan).
        SealedVault.resetForTest(app)
    }

    // -- Fields.matches (the page-match predicate) ------------------

    @Test
    fun `matches by the web domain's URL containment`() {
        val f = fields(domain = "github.com")
        assertTrue(f.matches(siteItem("gh", "https://github.com")))
        assertTrue("the substring match (a path form still matches)",
            f.matches(siteItem("gh", "https://github.com/login")))
        assertFalse(f.matches(siteItem("other", "https://example.com")))
    }

    @Test
    fun `the www prefix on the item's url still matches the bare domain`() {
        val f = fields(domain = "github.com")
        assertTrue(f.matches(siteItem("gh", "https://www.github.com")))
    }

    @Test
    fun `the app package is the fallback match (the no-domain forms)`() {
        val f = fields(pkg = "com.example.app", domain = null)
        assertTrue(f.matches(siteItem("app", "https://com.example.app")))
        assertFalse(f.matches(siteItem("web", "https://example.com")))
    }

    @Test
    fun `no domain and no package hit - no match (the registration case)`() {
        val f = fields(domain = "github.com")
        assertFalse("the empty urls never match", f.matches(siteItem("bare")))
    }

    // -- the ⚡ password chip's offer condition ----------------------

    @Test
    fun `the password chip - the registration case (a password field, no matching entry)`() {
        val f = fields(passwords = 1, domain = "github.com")
        assertTrue(svc.passwordChipOffered(f, listOf(siteItem("other", "https://example.com"))))
    }

    @Test
    fun `the password chip - offered even when an entry matches the page`() {
        // The user's call: the generate option must never be missing
        // from a password field — the matched entries fill alongside it.
        val f = fields(passwords = 1, domain = "github.com")
        assertTrue(svc.passwordChipOffered(
            f, listOf(siteItem("gh", "https://github.com"))))
    }

    @Test
    fun `the password chip - suppressed without a password field`() {
        val f = fields(usernames = 1, domain = "github.com")
        assertFalse("the zero-value dataset = the platform build() throws",
            svc.passwordChipOffered(f, emptyList()))
    }

    // -- the ✨ alias chip's offer condition -------------------------

    @Test
    fun `the alias chip - offered on any username form when the SL is linked`() {
        val f = fields(usernames = 1, passwords = 1, domain = "github.com")
        assertTrue("the matched site does NOT suppress it (the second account)",
            svc.aliasChipOffered(f, slReachable = true))
    }

    @Test
    fun `the alias chip - suppressed without a username or email field`() {
        val f = fields(passwords = 1, domain = "github.com")
        assertFalse(svc.aliasChipOffered(f, slReachable = true))
    }

    @Test
    fun `the alias chip - suppressed when the SL is unreachable`() {
        val f = fields(usernames = 1, domain = "github.com")
        assertFalse("not linked / the reveal failed",
            svc.aliasChipOffered(f, slReachable = false))
    }

    // -- the sealed manifest's SL uuid scan ---------------------------

    @Test
    fun `the sealed chip's label carries the clear-text identity`() {
        // The manifest's username/email = plaintext (the secrets stay
        // sealed) — the picker shows them without the unlock.
        val item = ProtonItem(name = "github.com",
            username = "user@x.test", urls = listOf("https://github.com"))
        assertEquals("github.com — user@x.test",
            svc.sealedLabel(item))
    }

    @Test
    fun `the sealed chip's label falls back to the email bucket`() {
        val item = ProtonItem(name = "github.com",
            email = "alias@aleeas.com", urls = listOf("https://github.com"))
        assertEquals("the email = the identity (username blank)",
            "github.com — alias@aleeas.com",
            svc.sealedLabel(item))
    }

    @Test
    fun `the sealed chip's label without an identity stays clean`() {
        assertEquals("github.com",
            svc.sealedLabel(ProtonItem(name = "github.com")))
    }

    @Test
    fun `the sealed label falls back to the url's host when the name is blank`() {
        val item = ProtonItem(name = "", username = "u@x.test",
            urls = listOf("https://gitlab.com"))
        val label = svc.sealedLabel(item)
        assertTrue("the host = the display name", label.contains("gitlab.com"))
        assertTrue("the identity still rides", label.contains("u@x.test"))
    }

    @Test
    fun `the sealed manifest yields the SL entry's uuid`() {
        val sl = ProtonItem(name = "SimpleLogin API",
            urls = listOf("https://app.simplelogin.io"), password = "THE-KEY")
        writeSealedCache(siteItem("gh", "https://github.com"), sl)
        assertEquals("the SL item's uuid — the chip rides it to the reveal",
            sl.itemUuid, svc.sealedSimpleLoginUuid())
    }

    @Test
    fun `no SL entry in the manifest - no sealed alias chip`() {
        writeSealedCache(siteItem("gh", "https://github.com"))
        assertNull(svc.sealedSimpleLoginUuid())
    }

    @Test
    fun `the SL detection rides the URL only (the name is irrelevant)`() {
        writeSealedCache(ProtonItem(name = "whatever",
            urls = listOf("https://app.simplelogin.io"), password = "K"))
        assertTrue(svc.sealedSimpleLoginUuid() != null)
    }
}
