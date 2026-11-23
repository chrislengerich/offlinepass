package com.offlinepass.app.simplelogin

import com.offlinepass.app.vault.ProtonItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * THE SIMPLELOGIN CHAIN (the alias chip's core logic): the fake client
 * (the canned responses = the real SL API's shapes, pinned by
 * SimpleLoginClientIntegrationTest) drives the chain; the asserts = the
 * item's build, the account's DEFAULT-domain (first-suffix) pick, and the error paths.
 */
class SimpleLoginChainTest {

    private class FakeClient(
        private val options: SimpleLoginClient.AliasOptions,
        private val mailboxes: List<SimpleLoginClient.Mailbox>,
        private val createdEmail: String = "github.word@aleeas.com",
    ) : SimpleLoginClient {
        override suspend fun randomAlias(apiKey: String, hostname: String?, mode: String?) =
            createdEmail
        override suspend fun listAliases(apiKey: String, pageId: Int, query: String?) = emptyList<SimpleLoginClient.AliasInfo>()
        override suspend fun toggleAlias(apiKey: String, aliasId: Long) = true
        override suspend fun aliasOptions(apiKey: String, hostname: String?) = options
        override suspend fun createCustomAlias(
            apiKey: String, prefix: String, signedSuffix: String,
            mailboxIds: List<Long>, hostname: String?,
        ): SimpleLoginClient.AliasInfo {
            // The REAL SL's response: the alias email = the prefix + the
            // UNSIGNED suffix (the signature rides the request only — the
            // created alias never carries the .SIG tail).
            return SimpleLoginClient.AliasInfo(
                id = 99L, email = prefix + signedSuffix.substringBefore(".SIG"),
                name = null, enabled = true, note = null)
        }
        override suspend fun mailboxes(apiKey: String) = mailboxes
        override suspend fun userInfo(apiKey: String) =
            SimpleLoginClient.UserInfo(name = null, email = createdEmail, isPremium = false)
    }

    /** The suffix list IN THE API'S ORDER — the first entry = the
     *  account's default domain. */
    private fun optionsWith(
        vararg domains: String,
        canCreate: Boolean = true,
        prefix: String? = "github",
    ): SimpleLoginClient.AliasOptions {
        val suffixes = domains.mapIndexed { i, d ->
            SimpleLoginClient.AliasOptions.Suffix(
                suffix = ".word@$d", signedSuffix = ".word@$d.SIG$i", isCustom = false)
        }
        return SimpleLoginClient.AliasOptions(
            canCreate = canCreate, prefixSuggestion = prefix, suffixes = suffixes)
    }

    private val mailboxes = listOf(
        SimpleLoginClient.Mailbox(id = 3L, email = "real@inbox.test", isDefault = true),
        SimpleLoginClient.Mailbox(id = 4L, email = "other@inbox.test", isDefault = false))

    @Test
    fun `the chain picks the account's DEFAULT (first) suffix and builds the fill item`() = kotlinx.coroutines.runBlocking {
        val opts = optionsWith("aleeas.com", "passmail.net")
        val item = SimpleLoginChain.createLinkedAlias(
            FakeClient(opts, mailboxes), "THE-KEY", "github.com", "generated-pw")
        assertEquals("the email/username = the created alias",
            "github.word@aleeas.com", item.email)
        assertEquals(item.email, item.username)
        assertEquals("generated-pw", item.password)
        assertEquals(listOf("https://github.com"), item.urls)
        assertEquals("the item's name = the site", "github.com", item.name)
    }

    @Test
    fun `no alias domains at all - the named error (the local fallback's trigger)`() = kotlinx.coroutines.runBlocking {
        val opts = optionsWith()
        val e = runCatching {
            SimpleLoginChain.createLinkedAlias(
                FakeClient(opts, mailboxes), "THE-KEY", "github.com", "pw")
        }.exceptionOrNull()
        assertTrue("the exception: $e",
            e is IllegalStateException && e.message?.contains("no alias domains") == true)
    }

    @Test
    fun `can_create false - the alias-limit error`() = kotlinx.coroutines.runBlocking {
        val opts = optionsWith("passmail.net", canCreate = false)
        val e = runCatching {
            SimpleLoginChain.createLinkedAlias(
                FakeClient(opts, mailboxes), "THE-KEY", "github.com", "pw")
        }.exceptionOrNull()
        assertTrue(e != null)
    }

    @Test
    fun `the hostname absent - the item's name and urls degrade gracefully`() = kotlinx.coroutines.runBlocking {
        val item = SimpleLoginChain.createLinkedAlias(
            FakeClient(optionsWith("aleeas.com"), mailboxes), "THE-KEY", null, "pw")
        assertEquals("Generated login", item.name)
        assertEquals(emptyList<String>(), item.urls)
    }

    @Test
    fun `the default mailbox is picked over the others`() = kotlinx.coroutines.runBlocking {
        val opts = optionsWith("aleeas.com")
        val fake = FakeClient(opts, mailboxes)
        // The mailboxes' order: the non-default first — the chain must
        // still pick the default.
        val shuffledMailboxes = listOf(mailboxes[1], mailboxes[0])
        val item = SimpleLoginChain.createLinkedAlias(
            object : SimpleLoginClient by fake {
                override suspend fun mailboxes(apiKey: String) = shuffledMailboxes
            }, "THE-KEY", "github.com", "pw")
        assertTrue("the created email = the first (default) domain",
            item.email.endsWith("@aleeas.com"))
    }
}
