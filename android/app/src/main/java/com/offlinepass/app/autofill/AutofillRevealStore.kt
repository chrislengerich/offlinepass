package com.offlinepass.app.autofill

import com.offlinepass.app.vault.ProtonItem

/**
 * The short-lived single-item reveal store for the sealed-state autofill:
 * the auth activity unseals ONE item (the same screenlock gate as the
 * item view), stores it here, and returns RESULT_OK — the autofill
 * framework then re-invokes onFillRequest, which fills from this store.
 * TTL-bound (60s) and replaced per unseal; the secrets never touch disk.
 */
object AutofillRevealStore {

    @Volatile private var item: ProtonItem? = null
    @Volatile private var datasetId: String? = null
    @Volatile private var at: Long = 0

    /** [id] = the DATASET id the offering chip carried ("generate" or the
     *  item's uuid) — the framework's re-invocation matches the
     *  authenticated dataset by id; the fill response must reuse it. */
    fun put(i: ProtonItem, id: String? = null) {
        item = i
        datasetId = id
        at = System.currentTimeMillis()
    }

    /** The fresh entry (within [maxAgeMs]) or null. Non-destructive: the
     *  framework may re-request per field. */
    fun peek(maxAgeMs: Long = 60_000): ProtonItem? =
        item?.takeIf { System.currentTimeMillis() - at < maxAgeMs }

    /** The dataset id of the current reveal (the auto-fill match key). */
    fun peekDatasetId(): String? = datasetId?.takeIf {
        item != null && System.currentTimeMillis() - at < 60_000
    }

    fun clear() {
        item = null
        datasetId = null
        at = 0
    }
}
