package com.offlinepass.app.vault

/**
 * Vault merging: union by `itemUuid` + tombstones, resolved by envelope
 * `rev` when both sides changed the same entry (the conflict UI's
 * union-merge option; keep-mine / take-theirs are degenerate calls).
 */
object VaultMerge {

    fun unionMerge(mine: Envelope, theirs: Envelope): Envelope {
        val merged = Envelope(
            rev = maxOf(mine.rev, theirs.rev) + 1,
            deviceId = mine.deviceId
        )
        val newerIs = if (theirs.rev > mine.rev) theirs else mine
        val olderIs = if (newerIs === mine) theirs else mine
        merged.deviceId = newerIs.deviceId.ifBlank { mine.deviceId }
        merged.extraFields.putAll(olderIs.extraFields)
        merged.extraFields.putAll(newerIs.extraFields)

        val byUuid = LinkedHashMap<String, ProtonItem>()
        fun addAll(env: Envelope, side: String) {
            for (item in env.items) {
                val existing = byUuid[item.itemUuid]
                if (existing == null) {
                    byUuid[item.itemUuid] = item
                    continue
                }
                // Same uuid on both sides: THE ITEM'S OWN modifyTime
                // decides — the envelope-rev rule LOST a locally-edited
                // entry when the other side's envelope rode a higher rev
                // without touching that item (the measured data loss). A
                // known modifyTime beats an unknown (0); equal/unknown on
                // both = the deterministic envelope-order fallback (the
                // newer envelope's copy). Tombstones still win below.
                if (item.modifyTime > existing.modifyTime) {
                    android.util.Log.i("VaultMerge",
                        "merge: ${item.itemUuid.take(8)} — the $side copy wins " +
                            "(modifyTime ${item.modifyTime} > ${existing.modifyTime})")
                    byUuid[item.itemUuid] = item
                } else if (item.modifyTime == existing.modifyTime && env === newerIs) {
                    if (item !== existing) android.util.Log.i("VaultMerge",
                        "merge: ${item.itemUuid.take(8)} — the $side copy wins " +
                            "(modifyTime tie ${item.modifyTime}, the newer envelope)")
                    byUuid[item.itemUuid] = item
                }
            }
        }
        addAll(olderIs, "older-envelope")
        addAll(newerIs, "newer-envelope")
        merged.items = byUuid.values
            .filter { it.itemUuid !in newerIs.deletedItemUuids && it.itemUuid !in olderIs.deletedItemUuids }
            .toMutableList()
        merged.deletedItemUuids = (newerIs.deletedItemUuids + olderIs.deletedItemUuids).toMutableSet()
        merged.removedDeviceIds = (newerIs.removedDeviceIds + olderIs.removedDeviceIds).toMutableSet()
        // Paired paste devices: union by keyId (== id); on the same keyId the
        // NEWER envelope's copy wins (items semantics) so seed re-wraps and
        // restores propagate through sync (R3). Removals tombstone.
        val devices = LinkedHashMap<String, DeviceRecord>()
        olderIs.devices.forEach { devices[it.keyId] = it }
        newerIs.devices.forEach { devices[it.keyId] = it }
        merged.devices = devices.values
            .filter { it.keyId !in merged.removedDeviceIds }
            .toMutableList()
        merged.items.sortBy { it.displayName.lowercase() }
        return merged
    }
}
