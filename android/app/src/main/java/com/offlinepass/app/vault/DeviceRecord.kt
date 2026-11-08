package com.offlinepass.app.vault

import org.json.JSONObject

/**
 * A paired paste target (Plan 2): a security-key credential whose public
 * ECDH key receives encrypted QRFT pastes from the Chrome extension.
 *
 * The record holds public data plus the extension's AES-GCM-wrapped seed —
 * the seed itself only exists inside the extension after a security-key
 * touch (WebAuthn PRF). `id` == `keyId` (SHA-256 of the public point, first
 * 8 bytes), which makes vault merges idempotent: re-pairing the same key
 * produces the same record.
 */
data class DeviceRecord(
    val id: String,
    val name: String,
    val credId: String,
    val pub: String,
    val keyId: String,
    val added: Long,
    val salt: String,
    val wrappedIv: String,
    val wrappedCt: String
) {
    fun toJsonObject(): JSONObject = JSONObject()
        .put("id", id)
        .put("name", name)
        .put("credId", credId)
        .put("pub", pub)
        .put("keyId", keyId)
        .put("added", added)
        .put("salt", salt)
        .put("wrapped", JSONObject().put("iv", wrappedIv).put("ct", wrappedCt))

    companion object {
        /** Payload `type` marker for pairing records flowing via QRFT. */
        const val PAYLOAD_TYPE = "linuxpass-device"

        fun fromJson(o: JSONObject): DeviceRecord? {
            val wrapped = o.optJSONObject("wrapped") ?: return null
            val keyId = o.optString("keyId", "")
            if (keyId.isEmpty()) return null
            return DeviceRecord(
                id = o.optString("id", keyId),
                name = o.optString("name", ""),
                credId = o.optString("credId", ""),
                pub = o.optString("pub", ""),
                keyId = keyId,
                added = o.optLong("added", 0),
                salt = o.optString("salt", ""),
                wrappedIv = wrapped.optString("iv", ""),
                wrappedCt = wrapped.optString("ct", "")
            )
        }

        /**
         * The pairing QRFT payload the extension emits:
         * `{"type":"linuxpass-device","device":{...}}`. Returns null for
         * anything else (item exports, envelopes, wrapped pastes).
         */
        fun fromPayload(raw: String): DeviceRecord? = runCatching {
            val obj = JSONObject(raw.trim())
            if (obj.optString("type") != PAYLOAD_TYPE) return@runCatching null
            fromJson(obj.getJSONObject("device"))
        }.getOrNull()
    }
}
