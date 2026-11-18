package com.offlinepass.app.vault

import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

/**
 * One login entry, ported from the desktop `passlib.ProtonItem` — the same
 * Proton Pass JSON shapes, so QR payloads and vault files round-trip with
 * the TUI unchanged.
 */
data class ProtonItem(
    var name: String = "",
    var username: String = "",
    var email: String = "",
    var password: String = "",
    var urls: List<String> = emptyList(),
    var note: String = "",
    var totpUri: String = "",
    /** Last modification, epoch seconds (Proton `modifyTime`). 0 = unknown. */
    var modifyTime: Long = 0,
    var itemUuid: String = UUID.randomUUID().toString(),
    var itemId: String = UUID.randomUUID().toString()
) {
    /** Best available display label: name, URL domain, or identity. */
    val displayName: String
        get() {
            if (name.isNotBlank()) return name
            urls.firstOrNull()?.let { u ->
                val host = u.removePrefix("https://").removePrefix("http://")
                    .substringBefore('/').substringBefore(':')
                if (host.isNotBlank()) return host
            }
            return username.ifBlank { email.ifBlank { "(unnamed)" } }
        }

    val identity: String get() = username.ifBlank { email }

    /** THE STUB MODEL: the secrets (the password/note/totpUri) are zeroed —
     *  they live in the sealed cache (the screenlock key) and the vault
     *  file (the card). The identity/search fields stay plaintext. */
    fun asStub(): ProtonItem = copy(password = "", note = "", totpUri = "")

    /** The secrets are present (a full/edited item, not a stub). */
    fun hasSecrets(): Boolean =
        password.isNotEmpty() || note.isNotEmpty() || totpUri.isNotEmpty()

    /** Human-readable last-modified stamp for list/detail rows. */
    val modifyTimeText: String
        get() {
            if (modifyTime <= 0) return "—"
            return java.time.Instant.ofEpochSecond(modifyTime)
                .atZone(java.time.ZoneId.systemDefault())
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"))
        }

    fun toProtonJson(): JSONObject {
        val content = JSONObject()
            .put("itemEmail", email)
            .put("itemUsername", username)
            .put("password", password)
            .put("urls", JSONArray(urls))
            .put("autofillUrls", JSONArray().apply {
                urls.forEach { put(JSONObject().put("url", it).put("mode", 0)) }
            })
            .put("totpUri", totpUri)
            .put("passkeys", JSONArray())
        return JSONObject()
            .put("itemId", itemId)
            .put("shareId", "local")
            .put("data", JSONObject()
                .put("type", "login")
                .put("metadata", JSONObject()
                    .put("name", name)
                    .put("note", note)
                    .put("itemUuid", itemUuid))
                .put("content", content)
                .put("extraFields", JSONArray())
                .put("platformSpecific", JSONObject()))
            .put("state", 1)
            .put("aliasEmail", JSONObject.NULL)
            .put("contentFormatVersion", 1)
            .put("createTime", 0)
            .put("modifyTime", modifyTime)
            .put("pinned", false)
            .put("shareCount", 0)
            .put("files", JSONArray())
    }

    companion object {
        fun fromJson(obj: JSONObject): ProtonItem {
            val data = obj.optJSONObject("data") ?: obj
            val meta = data.optJSONObject("metadata") ?: JSONObject()
            val content = data.optJSONObject("content") ?: JSONObject()
            return ProtonItem(
                name = meta.optString("name", ""),
                username = content.optString("itemUsername", ""),
                email = content.optString("itemEmail", ""),
                password = content.optString("password", ""),
                urls = content.optJSONArray("urls")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList(),
                note = meta.optString("note", ""),
                totpUri = content.optString("totpUri", ""),
                modifyTime = if (obj.has("modifyTime")) obj.optLong("modifyTime", 0)
                             else data.optLong("modifyTime", 0),
                itemUuid = meta.optString("itemUuid", UUID.randomUUID().toString()),
                itemId = obj.optString("itemId", UUID.randomUUID().toString())
            )
        }
    }
}
