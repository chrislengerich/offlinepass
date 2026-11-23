package com.offlinepass.app.simplelogin

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * THE SIMPLELOGIN CLIENT: the alias management over the documented API
 * (github.com/simple-login/app — docs/api.md). The auth = the per-device
 * API KEY in the `Authentication` header — no cookies, no OAuth (the
 * FIDO-2FA accounts create the key in the SL dashboard; the password
 * accounts can also mint it via /api/auth/login — not needed here since
 * the user pastes the dashboard-created key).
 *
 * The key NEVER persists outside the vault: it is read from the vault's
 * SimpleLogin item (the card-encrypted entry) transiently per operation,
 * held in RAM for the call's duration, and dropped with it.
 *
 * The base URL is overridable for the self-hosted instances.
 */
interface SimpleLoginClient {
    /** A new random alias. [hostname] = the site the alias is for
     *  (recommended). Returns the new alias's email. */
    suspend fun randomAlias(apiKey: String, hostname: String?, mode: String? = "word"): String

    /** The user's aliases, one page (20) at [pageId]; [query] filters by
     *  a substring (the email/name/note). Returns the alias summaries. */
    suspend fun listAliases(apiKey: String, pageId: Int = 0, query: String? = null): List<AliasInfo>

    /** Toggles an alias's enabled state; returns the NEW state. */
    suspend fun toggleAlias(apiKey: String, aliasId: Long): Boolean

    /** The v5 options: what the account can create right now. */
    data class AliasOptions(
        val canCreate: Boolean,
        val prefixSuggestion: String?,
        /** The signed suffixes filtered to ONE domain: the suffix, the
         *  signed form, and whether it is a custom domain. */
        val suffixes: List<Suffix>,
    ) {
        data class Suffix(val suffix: String, val signedSuffix: String, val isCustom: Boolean)
    }

    data class Mailbox(val id: Long, val email: String, val isDefault: Boolean)

    /** Creates a CUSTOM alias pinned to a domain: the prefix + the SIGNED
     *  suffix (from the v5 options) + the owning mailbox ids. */
    suspend fun createCustomAlias(
        apiKey: String,
        prefix: String,
        signedSuffix: String,
        mailboxIds: List<Long>,
        hostname: String? = null,
    ): AliasInfo

    /** The user's mailboxes (the create's owners; the default = first). */
    suspend fun mailboxes(apiKey: String): List<Mailbox>

    /** GET /api/user_info with the api key: the account identity — and
     *  THE KEY VALIDATION (401 = the wrong key). */
    suspend fun userInfo(apiKey: String): UserInfo

    data class UserInfo(val name: String?, val email: String, val isPremium: Boolean)

    /** The v5 options: what the account can create right now. */
    suspend fun aliasOptions(apiKey: String, hostname: String?): AliasOptions

    data class AliasInfo(
        val id: Long,
        val email: String,
        val name: String?,
        val enabled: Boolean,
        val note: String?,
    )
}

class SimpleLoginHttp(
    private val baseUrl: String = "https://app.simplelogin.io",
) : SimpleLoginClient {

    companion object {
        /** The SL API's uniform error: {error: "..."} with the status. */
        internal fun err(code: Int, body: String): String =
            "SimpleLogin API $code: ${runCatching {
                JSONObject(body).getString("error")
            }.getOrElse { body.take(120) }}"

        /** THE ALIAS LIST PARSE: the v2 response = {"aliases": [...],
         *  "collections": [...]} — each alias: id, email, name, enabled,
         *  note... */
        fun parseAliases(body: String): List<SimpleLoginClient.AliasInfo> {
            val arr = JSONObject(body).getJSONArray("aliases")
            return (0 until arr.length()).map { i ->
                val a = arr.getJSONObject(i)
                SimpleLoginClient.AliasInfo(
                    id = a.getLong("id"),
                    email = a.getString("email"),
                    name = a.optString("name").ifBlank { null },
                    enabled = a.optBoolean("enabled", true),
                    note = a.optString("note").ifBlank { null },
                )
            }
        }

        /** GET /api/user_info: {name, email, is_premium...} */
        fun parseUserInfo(body: String): SimpleLoginClient.UserInfo {
            val o = JSONObject(body)
            return SimpleLoginClient.UserInfo(
                name = o.optString("name").ifBlank { null },
                email = o.getString("email"),
                isPremium = o.optBoolean("is_premium", false))
        }

        /** The random/new response: {"alias": "..."} */
        fun parseNewAlias(body: String): String =
            JSONObject(body).getString("alias")

        /** The v5 options parse: can_create, the prefix suggestion, and
         *  the SIGNED suffixes. */
        fun parseAliasOptions(body: String): SimpleLoginClient.AliasOptions {
            val o = JSONObject(body)
            val suffixes = o.getJSONArray("suffixes")
            return SimpleLoginClient.AliasOptions(
                canCreate = o.optBoolean("can_create", false),
                prefixSuggestion = o.optString("prefix_suggestion").ifBlank { null },
                suffixes = (0 until suffixes.length()).map { i ->
                    val s = suffixes.getJSONObject(i)
                    SimpleLoginClient.AliasOptions.Suffix(
                        suffix = s.getString("suffix"),
                        signedSuffix = s.getString("signed_suffix"),
                        isCustom = s.optBoolean("is_custom", false))
                })
        }

        /** The mailboxes parse: the id, the email, the default flag. */
        fun parseMailboxes(body: String): List<SimpleLoginClient.Mailbox> {
            val arr = JSONObject(body).getJSONArray("mailboxes")
            return (0 until arr.length()).map { i ->
                val m = arr.getJSONObject(i)
                SimpleLoginClient.Mailbox(
                    id = m.getLong("id"),
                    email = m.getString("email"),
                    isDefault = m.optBoolean("default", false))
            }
        }

        /** The alias-info parse (the v3-custom's 201 shape = the same as
         *  GET /api/aliases/:id): the id, the email, the enabled. */
        fun parseAliasInfo(body: String): SimpleLoginClient.AliasInfo {
            val a = JSONObject(body)
            return SimpleLoginClient.AliasInfo(
                id = a.getLong("id"),
                email = a.getString("email"),
                name = a.optString("name").ifBlank { null },
                enabled = a.optBoolean("enabled", true),
                note = a.optString("note").ifBlank { null })
        }

        /** The toggle response: {"enabled": bool} */
        fun parseToggle(body: String): Boolean =
            JSONObject(body).getBoolean("enabled")
    }

    private suspend fun call(
        apiKey: String,
        path: String,
        query: Map<String, String> = emptyMap(),
        method: String = "GET",
        jsonBody: String? = null,
    ): Pair<Int, String> = withContext(Dispatchers.IO) {
        val qs = if (query.isEmpty()) "" else "?" + query.entries.joinToString("&") {
            "${URLEncoder.encode(it.key, "UTF-8")}=${URLEncoder.encode(it.value, "UTF-8")}"
        }
        val conn = (URL(baseUrl.trimEnd('/') + path + qs).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            setRequestProperty("Authentication", apiKey)
            setRequestProperty("Content-Type", "application/json")
            connectTimeout = 15_000
            readTimeout = 30_000
            if (jsonBody != null) doOutput = true
        }
        try {
            if (jsonBody != null) conn.outputStream.use { it.write(jsonBody.toByteArray()) }
            val code = conn.responseCode
            val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
                ?.bufferedReader()?.readText() ?: ""
            code to body
        } finally {
            conn.disconnect()
        }
    }

    override suspend fun randomAlias(apiKey: String, hostname: String?, mode: String?): String {
        val q = buildMap {
            hostname?.takeIf { it.isNotBlank() }?.let { put("hostname", it) }
            mode?.let { put("mode", it) }
        }
        val (code, body) = call(apiKey, "/api/alias/random/new", q, method = "POST", jsonBody = "{}")
        if (code !in 200..299) throw SimpleLoginException(err(code, body))
        return parseNewAlias(body)
    }

    override suspend fun listAliases(apiKey: String, pageId: Int, query: String?): List<SimpleLoginClient.AliasInfo> {
        val q = buildMap {
            put("page_id", pageId.toString())
            query?.takeIf { it.isNotBlank() }?.let { put("query", it) }
        }
        // The docs: the query rides the request BODY for the GET (the
        // frameworks' GET-body quirk) — the POST variant is equivalent.
        val (code, body) = call(apiKey, "/api/v2/aliases", q, method = "POST", jsonBody = "{}")
        if (code !in 200..299) throw SimpleLoginException(err(code, body))
        return parseAliases(body)
    }

    override suspend fun userInfo(apiKey: String): SimpleLoginClient.UserInfo {
        val (code, body) = call(apiKey, "/api/user_info")
        if (code == 401) throw SimpleLoginException("the SimpleLogin API key is incorrect")
        if (code !in 200..299) throw SimpleLoginException(err(code, body))
        return parseUserInfo(body)
    }

    override suspend fun toggleAlias(apiKey: String, aliasId: Long): Boolean {
        val (code, body) = call(apiKey, "/api/aliases/$aliasId/toggle", method = "POST")
        if (code !in 200..299) throw SimpleLoginException(err(code, body))
        return parseToggle(body)
    }

    override suspend fun aliasOptions(apiKey: String, hostname: String?): SimpleLoginClient.AliasOptions {
        val q = buildMap { hostname?.takeIf { it.isNotBlank() }?.let { put("hostname", it) } }
        val (code, body) = call(apiKey, "/api/v5/alias/options", q)
        if (code !in 200..299) throw SimpleLoginException(err(code, body))
        return parseAliasOptions(body)
    }

    override suspend fun mailboxes(apiKey: String): List<SimpleLoginClient.Mailbox> {
        val (code, body) = call(apiKey, "/api/v2/mailboxes")
        if (code !in 200..299) throw SimpleLoginException(err(code, body))
        return parseMailboxes(body)
    }

    override suspend fun createCustomAlias(
        apiKey: String, prefix: String, signedSuffix: String,
        mailboxIds: List<Long>, hostname: String?,
    ): SimpleLoginClient.AliasInfo {
        val q = buildMap { hostname?.takeIf { it.isNotBlank() }?.let { put("hostname", it) } }
        val payload = JSONObject().apply {
            put("alias_prefix", prefix)
            put("signed_suffix", signedSuffix)
            put("mailbox_ids", org.json.JSONArray(mailboxIds))
        }.toString()
        val (code, body) = call(apiKey, "/api/v3/alias/custom/new", q, method = "POST", jsonBody = payload)
        if (code != 201) throw SimpleLoginException(err(code, body))
        return parseAliasInfo(body)
    }
}

class SimpleLoginException(message: String) : Exception(message)
