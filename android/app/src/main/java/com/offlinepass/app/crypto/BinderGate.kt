package com.offlinepass.app.crypto

import android.os.IBinder
import kotlinx.coroutines.CompletableDeferred
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The once-guarded resolution of a ServiceConnection's callbacks. Android
 * can legitimately fire [onNullBinding] (the service returns a null
 * binder — disabled/unready) and [onBindingDied] (the host process died)
 * — NEITHER was handled before, and the awaiting coroutine hung forever:
 * the silent "decrypting vault…" freeze. Whichever callback fires FIRST
 * resolves the gate exactly once; the later ones are ignored.
 */
class BinderGate<T>(private val wrap: (IBinder) -> T?) {
    private val deferred = CompletableDeferred<T?>()
    private val resolved = AtomicBoolean(false)

    fun onServiceConnected(binder: IBinder) {
        if (resolved.compareAndSet(false, true)) {
            deferred.complete(wrap(binder))
        }
    }

    fun onNullBinding() {
        if (resolved.compareAndSet(false, true)) deferred.complete(null)
    }

    fun onBindingDied() = onNullBinding()

    suspend fun await(): T? = deferred.await()
}
