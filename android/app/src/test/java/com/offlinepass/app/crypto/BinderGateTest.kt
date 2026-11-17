package com.offlinepass.app.crypto

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * BinderGate: the once-guarded ServiceConnection resolution. Android's
 * callbacks can fire in orders the old code never handled — onNullBinding
 * and onBindingDied resolved NOTHING (the silent forever-hang inside the
 * decrypt). Whichever fires first must resolve exactly once.
 */
class BinderGateTest {

    private fun binder(): android.os.IBinder =
        org.mockito.Mockito.mock(android.os.IBinder::class.java)

    @Test
    fun connectedResolvesWithWrappedBinder() = runBlocking {
        val gate = BinderGate<String> { "wrapped:" + it.toString() }
        gate.onServiceConnected(binder())
        assertTrue((gate.await() ?: "").startsWith("wrapped:"))
    }

    @Test
    fun nullBindingResolvesNull_evenThenConnected() = runBlocking {
        val gate = BinderGate<String> { "wrapped" }
        gate.onNullBinding()
        // Android CAN fire onNullBinding and later onServiceConnected —
        // the first resolution wins; the second is ignored (no crash).
        gate.onServiceConnected(binder())
        assertNull(gate.await())
    }

    @Test
    fun connectedThenNullBindingKeepsFirstResolution() = runBlocking {
        val gate = BinderGate<String> { "wrapped" }
        gate.onServiceConnected(binder())
        gate.onNullBinding()
        assertEquals("wrapped", gate.await())
    }

    @Test
    fun bindingDiedResolvesNull() = runBlocking {
        val gate = BinderGate<String> { "wrapped" }
        gate.onBindingDied()
        assertNull(gate.await())
    }

    @Test
    fun noCallbackDoesNotResolve() = runBlocking {
        val gate = BinderGate<String> { "wrapped" }
        // The THE-BUG scenario: nothing fires → the await hangs forever.
        // The gate must NOT self-resolve; the caller's timeout governs.
        val resolved = kotlinx.coroutines.withTimeoutOrNull(150) { gate.await() }
        assertNull("the timeout must be the caller's safety net", resolved)
    }
}
