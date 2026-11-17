package com.offlinepass.app.autofill

import com.offlinepass.app.vault.ProtonItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The autofill reveal store: the auth activity unseals ONE item and stores
 * it; the framework's re-invoked onFillRequest fills from the fresh entry
 * (TTL 60s, non-destructive — the framework may re-request per field);
 * a second unseal replaces the first.
 */
class AutofillRevealStoreTest {

    private fun item(name: String) = ProtonItem(
        name = name, username = "$name@x", email = "", password = "pw-$name")

    @Test
    fun putThenPeekReturnsTheItem() {
        AutofillRevealStore.clear()
        AutofillRevealStore.put(item("a"))
        assertEquals("a", AutofillRevealStore.peek()?.name)
    }

    @Test
    fun secondUnsealReplacesTheFirst() {
        AutofillRevealStore.clear()
        AutofillRevealStore.put(item("a"))
        AutofillRevealStore.put(item("b"))
        assertEquals("b", AutofillRevealStore.peek()?.name)
    }

    @Test
    fun emptyStorePeeksNull() {
        AutofillRevealStore.clear()
        assertNull(AutofillRevealStore.peek())
    }

    @Test
    fun ttlExpiryDropsTheReveal() {
        AutofillRevealStore.clear()
        AutofillRevealStore.put(item("a"))
        Thread.sleep(2)
        assertTrue("a 1ms TTL must be expired", AutofillRevealStore.peek(1) == null)
    }
}
