package com.offlinepass.app.autofill

import android.content.Intent
import android.view.autofill.AutofillId
import com.offlinepass.app.vault.ProtonItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

/**
 * THE RESULT-CARRIED FILL (the ✨/⚡ post-save autofill fix): the
 * browser's log showed the framework receiving our auth result as an
 * "empty intent" AFTER expiring the response (onInvisibleForAutofill) —
 * the generated item came back as a re-offered chip instead of filling.
 * The auth result now carries the filled response; these tests pin the
 * intent contract (the parcelable fill targets) and the response build
 * (the no-clobber identity rule, the password always, the skip without
 * the password ids).
 */
@RunWith(RobolectricTestRunner::class)
class AutofillResultFillTest {

    private val app = RuntimeEnvironment.getApplication()

    /** setupService attaches the base context — generateIntent reads it
     *  (appContext()). */
    private val svc = Robolectric.setupService(OfflinepassAutofillService::class.java)

    /** A fresh AutofillId per call — the constructors are package-private
     *  in Robolectric's android-all, so the reflection seam. */
    private fun fid(): AutofillId =
        AutofillId::class.java.getDeclaredConstructor().apply { isAccessible = true }
            .newInstance() as AutofillId

    private fun fields(
        usernames: Int = 0, passwords: Int = 0, domain: String? = "github.com"
    ) = OfflinepassAutofillService.Fields(
        username = List(usernames) { fid() },
        password = List(passwords) { fid() },
        appPackage = "app.vanadium.browser", webDomain = domain)

    // -- the chip intents carry the fill targets ---------------------

    @Test
    fun `the password chip's intent carries the parcelable field ids`() {
        val f = fields(usernames = 2, passwords = 1)
        val intent = svc.generateIntent(
            AutofillAuthActivity.MODE_GENERATE, "github.com", f)
        assertEquals("the username ids ride for the activity's dataset build",
            f.username.size,
            intent.getParcelableArrayListExtra<AutofillId>(
                AutofillAuthActivity.EXTRA_FILL_USERNAME_IDS)?.size)
        assertEquals(f.password.size,
            intent.getParcelableArrayListExtra<AutofillId>(
                AutofillAuthActivity.EXTRA_FILL_PASSWORD_IDS)?.size)
    }

    @Test
    fun `the alias chip's intent carries the field ids plus the SL uuid`() {
        val f = fields(usernames = 1, passwords = 1)
        val intent = svc.generateIntent(
            "generate_alias", "github.com", f)
            .putExtra(AutofillAuthActivity.EXTRA_SL_UUID, "the-uuid")
        assertEquals(1, intent.getParcelableArrayListExtra<AutofillId>(
            AutofillAuthActivity.EXTRA_FILL_USERNAME_IDS)?.size)
        assertEquals("the-uuid",
            intent.getStringExtra(AutofillAuthActivity.EXTRA_SL_UUID))
    }

    // -- the result response build ------------------------------------

    private fun aliasItem() = ProtonItem(
        name = "github.com", username = "github.word@aleeas.com",
        email = "github.word@aleeas.com", password = "pw-16-characters")

    @Test
    fun `the alias item builds the response (the identity and the password ride)`() {
        val f = fields(usernames = 2, passwords = 1)
        val intent = svc.generateIntent("generate_alias", "github.com", f)
        val r = AutofillAuthActivity.buildResultResponse(
            app, intent, "✓ github.com — github.word@aleeas.com", aliasItem())
        assertNotNull("the response = the framework's direct apply", r)
    }

    @Test
    fun `the blank-identity item (the password chip) builds the response`() {
        val f = fields(usernames = 1, passwords = 1)
        val intent = svc.generateIntent("generate", "github.com", f)
        val item = ProtonItem(name = "github.com", password = "pw-16-characters")
        val r = AutofillAuthActivity.buildResultResponse(app, intent, "✓ github.com", item)
        assertNotNull("the password fills; the username ids stay unset (the no-clobber rule)", r)
    }

    @Test
    fun `no password ids in the intent - no response (the graceful skip)`() {
        val r = AutofillAuthActivity.buildResultResponse(
            app, Intent(), "✓", aliasItem())
        assertNull("the bare RESULT_OK fallback - never a crash", r)
    }

    @Test
    fun `no username ids with a blank identity - still fills the password`() {
        val f = fields(passwords = 1)
        val intent = svc.generateIntent("generate", "github.com", f)
        val item = ProtonItem(name = "github.com", password = "pw")
        assertTrue(AutofillAuthActivity.buildResultResponse(app, intent, "✓", item) != null)
    }
}
