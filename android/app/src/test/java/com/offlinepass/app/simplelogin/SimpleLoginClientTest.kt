package com.offlinepass.app.simplelogin

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * The SimpleLogin client's parse layer (no HTTP): the three responses'
 * shapes from docs/api.md, the error mapping, and the alias list's field
 * handling. (The Robolectric runner supplies the real org.json — the
 * plain JVM's android.jar carries only stubs.)
 */
@RunWith(RobolectricTestRunner::class)
class SimpleLoginClientTest {

    @Before
    fun setUp() {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "info")
    }

    @Test
    fun `the alias-list parse - the fields and the blank-string nulls`() {
        val body = """{"aliases":[
            {"id":17,"email":"quick.fox@passmail.net","name":"Quick",
             "enabled":true,"note":"for github","nb_block":0,"nb_forward":3},
            {"id":18,"email":"lazy.dog@passmail.net","name":"",
             "enabled":false,"note":""}
        ]}"""
        val aliases = SimpleLoginHttp.parseAliases(body)
        assertEquals(2, aliases.size)
        with(aliases[0]) {
            assertEquals(17L, id)
            assertEquals("quick.fox@passmail.net", email)
            assertEquals("Quick", name)
            assertTrue(enabled)
            assertEquals("for github", note)
        }
        with(aliases[1]) {
            assertEquals(null, name)
            assertFalse(enabled)
            assertEquals(null, note)
        }
    }

    @Test
    fun `the random-alias and the toggle parses`() {
        assertEquals("word.word@passmail.net",
            SimpleLoginHttp.parseNewAlias("""{"alias":"word.word@passmail.net"}"""))
        assertTrue(SimpleLoginHttp.parseToggle("""{"enabled":true}"""))
        assertFalse(SimpleLoginHttp.parseToggle("""{"enabled":false}"""))
    }

    @Test
    fun `the error mapping - the SL's error json surfaces by name`() {
        val message = SimpleLoginHttp.err(401, """{"error":"Wrong api key"}""")
        assertTrue(message.contains("401"))
        assertTrue(message.contains("Wrong api key"))
        // The non-JSON body = the raw head (120 chars max).
        val raw = SimpleLoginHttp.err(500, "<html>boom</html>")
        assertTrue(raw.contains("500"))
        assertTrue(raw.contains("<html>boom"))
    }
}
