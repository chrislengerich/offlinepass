package com.offlinepass.app.simplelogin

import com.offlinepass.app.vault.ProtonItem

/**
 * THE SIMPLELOGIN CHAIN (the alias chip's core logic, extracted from the
 * auth activity's MODE_GENERATE_ALIAS): the v5/options → the passmail.net
 * signed suffix → the v3-custom-create with the default mailbox → the
 * item with the alias in the email/username and the generated password.
 *
 * The client = the injectable interface — the tests drive the fake with
 * the canned responses (the same shapes the real SL API returns, pinned
 * by SimpleLoginClientIntegrationTest). The chain = suspend (the client's
 * methods are); the callers = the coroutines.
 */
object SimpleLoginChain {

    /** The alias domain the chain pins to. */
    const val SL_ALIAS_DOMAIN = "passmail.net"

    /** Creates the alias on the linked account (the hostname = the web
     *  origin) and builds the fill item: the email/username = the alias,
     *  the password = the generated. Throws when the account carries no
     *  passmail.net domain (the caller falls back to the local password). */
    suspend fun createLinkedAlias(
        client: SimpleLoginClient,
        apiKey: String,
        hostname: String?,
        password: String,
    ): ProtonItem {
        val opts = client.aliasOptions(apiKey, hostname)
        if (!opts.canCreate) {
            throw IllegalStateException(
                "the SimpleLogin account cannot create more aliases (the limit)")
        }
        val suffix = opts.suffixes.firstOrNull {
            it.suffix.endsWith("@$SL_ALIAS_DOMAIN")
        } ?: throw IllegalStateException(
            "no $SL_ALIAS_DOMAIN domain in the SL account")
        val mailbox = client.mailboxes(apiKey)
            .firstOrNull { it.isDefault } ?: client.mailboxes(apiKey).first()
        val created = client.createCustomAlias(
            apiKey,
            prefix = opts.prefixSuggestion ?: "alias",
            signedSuffix = suffix.signedSuffix,
            mailboxIds = listOf(mailbox.id),
            hostname = hostname)
        return ProtonItem(
            name = hostname ?: "Generated login",
            email = created.email,
            username = created.email,
            urls = hostname?.let { listOf("https://$it") } ?: emptyList(),
            password = password)
    }
}
