package com.offlinepass.app.simplelogin

import com.offlinepass.app.vault.ProtonItem

/**
 * THE SIMPLELOGIN CHAIN (the alias creation shared by the Add-entry page
 * and the autofill's alias chip): the v5/options → the account's DEFAULT
 * domain (the first suffix the API offers — SimpleLogin already scopes
 * the list to what the account can create on) → the v3-custom-create
 * with the default mailbox → the alias email.
 *
 * The client = the injectable interface — the tests drive the fake with
 * the canned responses (the same shapes the real SL API returns, pinned
 * by SimpleLoginClientIntegrationTest). The chain = suspend (the
 * client's methods are); the callers = the coroutines.
 */
object SimpleLoginChain {

    /** Creates the alias on the linked account (the hostname = the web
     *  origin) and returns its email. Throws a named error when the
     *  account cannot create (the limit, no domains) — the callers fall
     *  back to the local password. */
    suspend fun createAlias(
        client: SimpleLoginClient,
        apiKey: String,
        hostname: String?,
    ): String {
        val opts = client.aliasOptions(apiKey, hostname)
        if (!opts.canCreate) {
            throw IllegalStateException(
                "the SimpleLogin account cannot create more aliases (the limit)")
        }
        // THE DEFAULT DOMAIN: the first offered suffix — the account's
        // own default (SimpleLogin returns only the usable domains).
        val suffix = opts.suffixes.firstOrNull()
            ?: throw IllegalStateException(
                "the SimpleLogin account has no alias domains")
        val mailbox = client.mailboxes(apiKey)
            .firstOrNull { it.isDefault } ?: client.mailboxes(apiKey).first()
        val created = client.createCustomAlias(
            apiKey,
            prefix = opts.prefixSuggestion ?: "alias",
            signedSuffix = suffix.signedSuffix,
            mailboxIds = listOf(mailbox.id),
            hostname = hostname)
        return created.email
    }

    /** Creates the alias and builds the fill item: the email/username =
     *  the alias, the password = the generated. */
    suspend fun createLinkedAlias(
        client: SimpleLoginClient,
        apiKey: String,
        hostname: String?,
        password: String,
    ): ProtonItem {
        val alias = createAlias(client, apiKey, hostname)
        return ProtonItem(
            name = hostname ?: "Generated login",
            email = alias,
            username = alias,
            urls = hostname?.let { listOf("https://$it") } ?: emptyList(),
            password = password)
    }
}
