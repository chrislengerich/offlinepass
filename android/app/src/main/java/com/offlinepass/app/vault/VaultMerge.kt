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
        fun addAll(env: Envelope) {
            for (item in env.items) {
                val existing = byUuid[item.itemUuid]
                if (existing == null) byUuid[item.itemUuid] = item
                // Same uuid on both sides: the newer envelope's copy wins.
            }
        }
        addAll(olderIs)
        addAll(newerIs)
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
