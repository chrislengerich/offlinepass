package com.linuxpass.app.vault

import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

/**
 * The vault envelope: Proton Pass vaults JSON plus the sync bookkeeping the
 * desktop side now preserves — `rev` (monotonic, bumps per save) and
 * `deviceId`. Unknown top-level fields survive round-trips (the app never
 * rebuilds the envelope from scratch on load).
 */
data class Envelope(
    var rev: Long = 0,
    var deviceId: String = "",
    var items: MutableList<ProtonItem> = mutableListOf(),
    /** `itemUuid`s deleted here (or seen deleted elsewhere); survives merges. */
    var deletedItemUuids: MutableSet<String> = mutableSetOf(),
    /** Paired paste targets (Chrome extension security keys); union-merged. */
    var devices: MutableList<DeviceRecord> = mutableListOf(),
    /** Device records removed on any side; merges honor these. */
    var removedDeviceIds: MutableSet<String> = mutableSetOf(),
    /** Any top-level fields the app does not model, preserved verbatim. */
    var extraFields: MutableMap<String, Any?> = linkedMapOf()
) {
    fun toJsonObject(): JSONObject {
        val vaultItems = JSONArray().apply { items.forEach { put(it.toProtonJson()) } }
        val vault = JSONObject()
            .put("name", "Personal")
            .put("description", "")
            .put("display", JSONObject().put("color", 0).put("icon", 0))
            .put("items", vaultItems)
        val out = JSONObject()
            .put("userId", "local")
            .put("version", "1.0")
            .put("vaults", JSONObject().put("local", vault))
            .put("rev", rev)
            .put("deviceId", deviceId)
            .put("deletedItemUuids", JSONArray().apply { deletedItemUuids.forEach { put(it) } })
        if (devices.isNotEmpty()) {
            out.put("devices", JSONArray().apply { devices.forEach { put(it.toJsonObject()) } })
        }
        if (removedDeviceIds.isNotEmpty()) {
            out.put("removedDeviceIds", JSONArray().apply { removedDeviceIds.forEach { put(it) } })
        }
        extraFields.forEach { (k, v) -> if (out.has(k).not()) out.put(k, v ?: JSONObject.NULL) }
        return out
    }

    companion object {
        fun fromJson(raw: String): Envelope {
            // Array shape (a bare list of items) first — the rest is objects.
            if (raw.trimStart().startsWith("[")) {
                val arr = JSONArray(raw)
                val arrayItems = mutableListOf<ProtonItem>()
                for (i in 0 until arr.length()) arrayItems += ProtonItem.fromJson(arr.getJSONObject(i))
                arrayItems.sortBy { it.displayName.lowercase() }
                return Envelope(items = arrayItems)
            }
            val obj = JSONObject(raw)
            val items = mutableListOf<ProtonItem>()
            if (obj.has("vaults")) {
                val vaults = obj.getJSONObject("vaults")
                for (key in vaults.keys()) {
                    val vault = vaults.getJSONObject(key)
                    vault.optJSONArray("items")?.let { arr ->
                        for (i in 0 until arr.length()) items += ProtonItem.fromJson(arr.getJSONObject(i))
                    }
                }
            } else if (obj.has("data")) {
                items += ProtonItem.fromJson(obj)
            }
            items.sortBy { it.displayName.lowercase() }
            val known = setOf("userId", "version", "vaults", "rev", "deviceId", "deletedItemUuids",
                "devices", "removedDeviceIds")
            val extras = linkedMapOf<String, Any?>()
            for (key in obj.keys()) if (key !in known) extras[key] = obj.get(key)
            return Envelope(
                rev = obj.optLong("rev", 0),
                deviceId = obj.optString("deviceId", ""),
                items = items,
                deletedItemUuids = obj.optJSONArray("deletedItemUuids")
                    ?.let { a -> (0 until a.length()).map { a.getString(it) }.toMutableSet() }
                    ?: mutableSetOf(),
                devices = obj.optJSONArray("devices")
                    ?.let { a -> (0 until a.length()).mapNotNull { DeviceRecord.fromJson(a.getJSONObject(it)) }.toMutableList() }
                    ?: mutableListOf(),
                removedDeviceIds = obj.optJSONArray("removedDeviceIds")
                    ?.let { a -> (0 until a.length()).map { a.getString(it) }.toMutableSet() }
                    ?: mutableSetOf(),
                extraFields = extras
            )
        }

        /** A fresh empty envelope for the new-vault flow. */
        fun empty(deviceId: String): Envelope = Envelope(rev = 1, deviceId = deviceId)

        /**
         * Import from a Proton Pass EXPORT file (plaintext!) vs an encrypted
         * vault: plaintext JSON (list- or envelope-shaped) parses to an
         * Envelope; anything else (PGP armor/binary) returns null and the
         * caller decrypts first. This is the "Import from Proton Pass" path.
         */
        fun parseImport(raw: String): Envelope? {
            val t = raw.trimStart()
            if (!(t.startsWith("{") || t.startsWith("["))) return null
            return runCatching { fromJson(t) }.getOrNull()
        }
    }
}
