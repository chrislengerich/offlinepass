package com.linuxpass.app.vault

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
            .put("modifyTime", 0)
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
                itemUuid = meta.optString("itemUuid", UUID.randomUUID().toString()),
                itemId = obj.optString("itemId", UUID.randomUUID().toString())
            )
        }
    }
}
