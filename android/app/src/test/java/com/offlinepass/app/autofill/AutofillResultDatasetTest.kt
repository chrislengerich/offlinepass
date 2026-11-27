package com.offlinepass.app.autofill

import android.content.Intent
import android.os.Parcel
import android.service.autofill.Dataset
import android.view.autofill.AutofillId
import com.offlinepass.app.vault.ProtonItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

/**
 * THE RESULT-DATASET CONTRACT (the measured Vanadium no-fill): the auth
 * result must fill whatever the page offered — the username-only pages
 * (Proton's step 1, the SSO forms) included. The old guard demanded
 * password ids and returned null on their absence: RESULT_OK with an
 * EMPTY result, the username field untouched, no re-invoke. The
 * zero-value trap stays pinned too: a dataset with no values makes the
 * platform's build() throw — the service shares the app's process.
 */
@RunWith(RobolectricTestRunner::class)
class AutofillResultDatasetTest {

    private val context = RuntimeEnvironment.getApplication()

    /** A fresh AutofillId per call (the constructors are package-private
     *  in Robolectric's android-all — the reflection seam). */
    private fun fid(): AutofillId =
        AutofillId::class.java.getDeclaredConstructor().apply { isAccessible = true }
            .newInstance() as AutofillId

    /** AutofillId is Parcelable; the intent carries ArrayLists. */
    private fun ids(vararg ids: AutofillId) = ArrayList(listOf(*ids))

    private fun intent(userIds: List<AutofillId>, pwIds: List<AutofillId>,
                       emailIds: List<AutofillId> = emptyList()) = Intent().apply {
        putParcelableArrayListExtra(AutofillAuthActivity.EXTRA_FILL_USERNAME_IDS, ids(*userIds.toTypedArray()))
        putParcelableArrayListExtra(AutofillAuthActivity.EXTRA_FILL_EMAIL_IDS, ids(*emailIds.toTypedArray()))
        putParcelableArrayListExtra(AutofillAuthActivity.EXTRA_FILL_PASSWORD_IDS, ids(*pwIds.toTypedArray()))
    }

    @Test
    fun usernameOnlyPageBuildsTheDataset() {
        // THE MEASURED BUG's shape: 1 username id, no password field.
        val item = ProtonItem(name = "Proton", username = "chris@proton.me")
        val ds = AutofillAuthActivity.buildResultDataset(
            context, intent(listOf(fid()), emptyList()), "✓ Proton", item)
        assertNotNull("the username-only reveal MUST fill", ds)
    }

    @Test
    fun bothListsPresentBuildsTheDataset() {
        val item = ProtonItem(name = "S", username = "u", password = "p")
        val ds = AutofillAuthActivity.buildResultDataset(
            context, intent(listOf(fid()), listOf(fid())), "✓ S", item)
        assertNotNull(ds)
    }

    @Test
    fun passwordOnlyPageBuildsTheDataset() {
        val item = ProtonItem(name = "S", password = "p")
        val ds = AutofillAuthActivity.buildResultDataset(
            context, intent(emptyList(), listOf(fid())), "✓ S", item)
        assertNotNull(ds)
    }

    @Test
    fun nothingToFillYieldsNull() {
        val item = ProtonItem(name = "S", username = "u", password = "p")
        val ds = AutofillAuthActivity.buildResultDataset(
            context, intent(emptyList(), emptyList()), "✓ S", item)
        assertNull("no ids = no dataset (the zero-value trap)", ds)
    }

    @Test
    fun blankIdentityWithNoPasswordIdsYieldsNull() {
        // The zero-value trap's edge: a blank identity fills no username,
        // no password ids exist → zero pairs → build() would THROW.
        val item = ProtonItem(name = "S", username = "", email = "")
        val ds = AutofillAuthActivity.buildResultDataset(
            context, intent(listOf(fid()), emptyList()), "✓ S", item)
        assertNull(ds)
    }

    @Test
    fun theDatasetParcelsCleanly() {
        // The result rides an Intent across the framework boundary —
        // the parcel round-trip is part of the contract.
        val ds = AutofillAuthActivity.buildResultDataset(
            context, intent(listOf(fid()), listOf(fid())),
            "✓ S", ProtonItem(name = "S", username = "u", password = "p"))!!
        val p = Parcel.obtain()
        try {
            ds.writeToParcel(p, 0)
            p.setDataPosition(0)
            assertNotNull(Dataset.CREATOR.createFromParcel(p))
        } finally { p.recycle() }
        assertTrue(true)
    }

    // -- THE FILL-PAIRS RULE (the value mapping — the thing a Dataset
    //    can't be introspected for) ------------------------------------------

    @Test
    fun theSignupShapeFillsEachBoxItsOwnValue() {
        // THE MEASURED WRONGNESS: a form with a username box AND an email
        // box — the old single-bucket fill put the SAME value (the
        // identity) in both. Now: the username box gets the username, the
        // email box gets the item's email.
        val user = fid(); val mail = fid(); val pw = fid()
        val item = ProtonItem(name = "S", username = "chris", email = "chris@proton.me")
        val pairs = fillPairs(listOf(user), listOf(mail), listOf(pw), item)
        assertTrue(pairs.contains(user to "chris"))
        assertTrue(pairs.contains(mail to "chris@proton.me"))
        assertTrue(pairs.contains(pw to item.password))
        assertEquals(3, pairs.size)
    }

    @Test
    fun emailOnlyItemFillsTheEmailBoxWithTheIdentity() {
        // An email-only item (no separate username): the email box gets
        // the identity (which IS the email).
        val mail = fid()
        val item = ProtonItem(name = "S", email = "only@proton.me")
        val pairs = fillPairs(null, listOf(mail), null, item)
        assertTrue(pairs.contains(mail to "only@proton.me"))
    }

    @Test
    fun blankEmailOnTheItemFallsBackToTheIdentityInTheEmailBox() {
        val mail = fid()
        val item = ProtonItem(name = "S", username = "chris")
        val pairs = fillPairs(null, listOf(mail), null, item)
        assertTrue(pairs.contains(mail to "chris"))
    }

    @Test
    fun blanksFillNothingButThePasswordAlwaysRides() {
        // The no-clobber rule for the identity sides; the password side
        // keeps the historical always-fill semantics.
        val user = fid(); val mail = fid(); val pw = fid()
        val item = ProtonItem(name = "S", username = "", email = "", password = "")
        val pairs = fillPairs(listOf(user), listOf(mail), listOf(pw), item)
        assertTrue(pairs.contains(pw to ""))
        assertEquals("the identity sides stay unset", 1, pairs.size)
    }
}
