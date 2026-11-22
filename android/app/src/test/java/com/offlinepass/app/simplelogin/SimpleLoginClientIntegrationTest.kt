package com.offlinepass.app.simplelogin

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import kotlinx.coroutines.runBlocking
import java.util.Collections
import org.robolectric.RobolectricTestRunner
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.ServerSocket
import java.net.Socket
import java.net.URLDecoder
import kotlin.concurrent.thread

/**
 * THE SIMPLELOGIN CLIENT'S HTTP CONTRACT, exercised end-to-end against a
 * hand-rolled stub server (a raw ServerSocket on 127.0.0.1 — zero deps,
 * the plain JVM): the request shapes (the paths, the query, the POST
 * bodies, the Authentication header) and the response handling (the
 * parses, the error mapping) for every call the app makes. The
 * Robolectric runner supplies the real org.json (the plain JVM's
 * android.jar = stubs).
 */
@RunWith(RobolectricTestRunner::class)
class SimpleLoginClientIntegrationTest {

    data class Request(
        val method: String,
        val pathWithQuery: String,
        val authHeader: String?,
        val body: String,
    )

    /** The path-prefix → (the status, the body) canned responses. */
    private val canned = linkedMapOf<String, Pair<Int, String>>()
    private val recorded = Collections.synchronizedList(mutableListOf<Request>())
    private var server: ServerSocket? = null

    private var stubHandler: ((Request) -> Pair<Int, String>)? = null

    @Before
    fun setUp() {
        recorded.clear()
        canned.clear()
        val socket = ServerSocket(0)
        server = socket
        stubHandler = { request ->
            val hit = canned.entries.firstOrNull { request.pathWithQuery.startsWith(it.key) }
            hit?.value ?: (404 to """{"error":"not stubbed"}""")
        }
        thread(isDaemon = true) {
            while (!socket.isClosed) {
                val conn = try {
                    socket.accept()
                } catch (e: Exception) {
                    return@thread
                }
                thread(isDaemon = true) {
                    try {
                        conn.use { c ->
                            val reader = BufferedReader(InputStreamReader(c.getInputStream()))
                            val requestLine = reader.readLine() ?: return@use
                            val parts = requestLine.split(" ")
                            if (parts.size < 2) return@use
                            val method = parts[0]
                            val pathWithQuery = parts[1]
                            val headers = mutableMapOf<String, String>()
                            while (true) {
                                val h = reader.readLine() ?: break
                                if (h.isEmpty()) break
                                val idx = h.indexOf(':')
                                if (idx > 0) headers[h.substring(0, idx).trim().lowercase()] =
                                    h.substring(idx + 1).trim()
                            }
                            val contentLength = headers["content-length"]?.toIntOrNull() ?: 0
                            val body = if (contentLength > 0) {
                                val buf = CharArray(contentLength)
                                reader.read(buf, 0, contentLength)
                                String(buf)
                            } else ""
                            val request = Request(method, pathWithQuery,
                                headers["authentication"], body)
                            recorded.add(request)
                            val (status, respBody) = (stubHandler ?: { 404 to "" })(request)
                            val bytes = respBody.toByteArray(Charsets.UTF_8)
                            c.getOutputStream().write(
                                ("HTTP/1.1 $status OK\r\n" +
                                    "Content-Type: application/json\r\n" +
                                    "Content-Length: ${bytes.size}\r\n" +
                                    "Connection: close\r\n\r\n").toByteArray() + bytes)
                            c.getOutputStream().flush()
                        }
                    } catch (e: Exception) {
                        // the client hung up mid-request — the next accept
                    }
                }
            }
        }
    }

    @After
    fun tearDown() {
        server?.close()
        server = null
    }

    private fun client() = SimpleLoginHttp(
        baseUrl = "http://127.0.0.1:${server!!.localPort}")

    private fun lastRequestFor(pathPrefix: String): Request =
        recorded.last { it.pathWithQuery.startsWith(pathPrefix) }

    // -- listAliases ---------------------------------------------------------

    @Test
    fun `listAliases posts with the auth header and parses the list`() {
        canned["/api/v2/aliases"] = 200 to
            """{"aliases":[
                {"id":17,"email":"quick.fox@passmail.net","name":"Quick",
                 "enabled":true,"note":"for github"},
                {"id":18,"email":"lazy.dog@passmail.net","name":"",
                 "enabled":false,"note":""}
            ]}"""
        val aliases = runBlocking { client().listAliases("THE-KEY", 0, "github") }
        assertEquals(2, aliases.size)
        assertEquals("quick.fox@passmail.net", aliases[0].email)
        assertEquals("Quick", aliases[0].name)
        assertTrue(aliases[0].enabled)
        assertFalse(aliases[1].enabled)
        // The request shape: the POST (the query-in-body quirk), the auth
        // header, the page_id in the query.
        val rec = lastRequestFor("/api/v2/aliases")
        assertEquals("POST", rec.method)
        assertTrue(rec.pathWithQuery.startsWith("/api/v2/aliases?page_id=0"))
        assertEquals("THE-KEY", rec.authHeader)
    }

    @Test
    fun `listAliases carries the query filter in the body`() {
        canned["/api/v2/aliases"] = 200 to """{"aliases":[]}"""
        runBlocking { client().listAliases("THE-KEY", 2, "passmail") }
        val rec = lastRequestFor("/api/v2/aliases")
        assertEquals("POST", rec.method)
        assertTrue(rec.pathWithQuery.contains("query=passmail"))
        assertTrue(rec.pathWithQuery.startsWith("/api/v2/aliases?page_id=2"))
    }

    // -- toggleAlias ---------------------------------------------------------

    @Test
    fun `toggleAlias posts to the toggle path and returns the new state`() {
        canned["/api/aliases/17/toggle"] = 200 to """{"enabled": false}"""
        val enabled = runBlocking { client().toggleAlias("THE-KEY", 17L) }
        assertFalse("the toggle returns the NEW state", enabled)
        val rec = lastRequestFor("/api/aliases/17/toggle")
        assertEquals("POST", rec.method)
        assertEquals("THE-KEY", rec.authHeader)
    }

    // -- randomAlias ----------------------------------------------------------

    @Test
    fun `randomAlias posts with the hostname and mode in the query`() {
        canned["/api/alias/random/new"] = 200 to """{"alias":"lumping498@aleeas.com"}"""
        val alias = runBlocking { client().randomAlias("THE-KEY", "github.com", "word") }
        assertEquals("lumping498@aleeas.com", alias)
        val rec = lastRequestFor("/api/alias/random/new")
        assertEquals("POST", rec.method)
        assertTrue(rec.pathWithQuery.contains("hostname=github.com"))
        assertTrue(rec.pathWithQuery.contains("mode=word"))
    }

    // -- the create chain: options → mailboxes → v3 custom/new ----------------

    @Test
    fun `createCustomAlias chains options, mailboxes, and create with the passmail suffix`() {
        // 1. The options: the account's domains (the passmail.net + the
        //    other), the can_create, the prefix suggestion.
        canned["/api/v5/alias/options"] = 200 to
            """{"can_create":true,"prefix_suggestion":"github",
                "suffixes":[
                    {"suffix":".word@passmail.net",
                     "signed_suffix":".word@passmail.net.SIG123",
                     "is_custom":true},
                    {"suffix":".cat@aleeas.com",
                     "signed_suffix":".cat@aleeas.com.SIG456",
                     "is_custom":false}
                ]}"""
        // 2. The mailboxes: the default = the first.
        canned["/api/v2/mailboxes"] = 200 to
            """{"mailboxes":[
                {"id":3,"email":"real@inbox.test","default":true},
                {"id":4,"email":"other@inbox.test","default":false}
            ]}"""
        // 3. The create: 201 with the alias-info shape.
        canned["/api/v3/alias/custom/new"] = 201 to
            """{"id":99,"email":"github.word@passmail.net","name":"github",
                "enabled":true,"note":""}"""

        val created = runBlocking {
            client().createCustomAlias("THE-KEY", prefix = "github",
                signedSuffix = ".word@passmail.net.SIG123",
                mailboxIds = listOf(3L), hostname = "github.com")
        }
        assertEquals(99L, created.id)
        assertEquals("github.word@passmail.net", created.email)
        assertTrue(created.enabled)

        // The request order: the options → the mailboxes → the create.
        val paths = recorded.map { it.pathWithQuery.substringBefore('?') }
        System.out.println("DBG recorded: " + recorded.map { it.method + " " + it.pathWithQuery + " auth=" + it.authHeader + " body=" + it.body.take(60) })
        assertTrue(paths.indexOf("/api/v5/alias/options") <= paths.indexOf("/api/v2/mailboxes"))

        // The create's POST body: the prefix, the SIGNED suffix, and the
        // owning mailbox id.
        val createRec = lastRequestFor("/api/v3/alias/custom/new")
        assertEquals("POST", createRec.method)
        assertTrue(createRec.body.contains("\"alias_prefix\":\"github\""))
        assertTrue(createRec.body.contains("\"signed_suffix\":\".word@passmail.net.SIG123\""))
        assertTrue(createRec.body.contains("\"mailbox_ids\":[3]"))
    }

    // -- userInfo --------------------------------------------------------------

    @Test
    fun `userInfo parses the identity`() {
        canned["/api/user_info"] = 200 to
            """{"name":"John Wick","email":"john@wick.com",
                "is_premium":false,"max_alias_free_plan":5}"""
        val info = runBlocking { client().userInfo("THE-KEY") }
        assertEquals("john@wick.com", info.email)
        assertEquals("John Wick", info.name)
        assertFalse(info.isPremium)
    }

    // -- the error mapping ------------------------------------------------------

    @Test
    fun `the SL error json surfaces by name`() {
        canned["/api/v2/aliases"] = 500 to """{"error":"the alias limit is reached"}"""
        val e = runCatching { runBlocking { client().listAliases("THE-KEY") } }
            .exceptionOrNull()
        assertTrue("the exception: $e", e is SimpleLoginException)
        assertTrue(e?.message?.contains("500") == true)
        assertTrue(e?.message?.contains("the alias limit is reached") == true)
    }

    @Test
    fun `the non-json error body surfaces the raw head`() {
        canned["/api/v2/aliases"] = 500 to "<html>boom</html>"
        val e = runCatching { runBlocking { client().listAliases("THE-KEY") } }
            .exceptionOrNull()
        assertTrue(e?.message?.contains("<html>boom") == true)
    }

    // -- the auth header on EVERY request ----------------------------------------

    @Test
    fun `the Authentication header rides every request`() {
        canned["/api/v2/aliases"] = 200 to """{"aliases":[]}"""
        canned["/api/aliases/17/toggle"] = 200 to """{"enabled":true}"""
        canned["/api/alias/random/new"] = 200 to """{"alias":"x"}"""
        canned["/api/user_info"] = 200 to """{"email":"e"}"""
        canned["/api/v5/alias/options"] = 200 to """{"suffixes":[]}"""
        canned["/api/v2/mailboxes"] = 200 to """{"mailboxes":[]}"""
        runBlocking {
            client().listAliases("K")
            client().toggleAlias("K", 17L)
            client().randomAlias("K", "e.com", "word")
            client().userInfo("K")
            client().aliasOptions("K", "e.com")
            client().mailboxes("K")
        }
        val markerCount = recorded.count { it.authHeader == "K" }
        assertEquals("every request carries the auth header", 6, markerCount)
    }
}
