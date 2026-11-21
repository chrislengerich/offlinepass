package com.offlinepass.app.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** The GOOGLE PASSWORDS CSV round-trips: the parse (the picked GPM/Chrome
 *  export → login items) and the serialize (the items → the CSV Chrome's
 *  import accepts back), the RFC-4180 quoting included. */
@RunWith(RobolectricTestRunner::class)
class GoogleCsvTest {

    /** A real-shaped Google Password Manager export. */
    private val export = "\"name\",\"url\",\"username\",\"password\"\n" +
        "\"GitHub\",\"https://github.com\",\"ko\",\"pw1\"\n" +
        "\"Shop\",\"https://shop.example\",\"ko@example.com\",\"co,mma \"\"quoted\"\"\"\n" +
        "\"App\",\"\",\"appuser\",\"line1\nline2\"\n"

    @Test
    fun parsesTheRealShapedExport() {
        val items = GooglePasswordsCsv.parse(export)
        assertEquals(3, items.size)
        val github = items[0]
        assertEquals("GitHub", github.name)
        assertEquals("ko", github.username)
        assertEquals("pw1", github.password)
        assertEquals(listOf("https://github.com"), github.urls)
        // The email-shaped username lands on itemUsername (the display
        // identity falls through to it).
        assertEquals("ko@example.com", items[1].username)
    }

    @Test
    fun rfc4180QuotingSurvives() {
        val items = GooglePasswordsCsv.parse(export)
        assertEquals("co,mma \"quoted\"", items[1].password)
        assertEquals("line1\nline2", items[2].password)
        // The app entry: an empty url = no urls (Google app rows).
        assertTrue(items[2].urls.isEmpty())
        assertEquals("App", items[2].displayName)
    }

    @Test
    fun exportThenImportRoundTrips() {
        val original = listOf(
            ProtonItem(
                name = "A, B", username = "u\"1", password = "p\nw",
                urls = listOf("https://a.example")
            ),
            ProtonItem(name = "App", username = "au", password = "plain")
        )
        val again = GooglePasswordsCsv.parse(GooglePasswordsCsv.serialize(original))
        assertEquals(original.map { it.name }, again.map { it.name })
        assertEquals(original.map { it.username }, again.map { it.username })
        assertEquals(original.map { it.password }, again.map { it.password })
        assertEquals(original.map { it.urls }, again.map { it.urls })
    }

    @Test
    fun serializeQuotesOnlyWhenNeeded() {
        val csv = GooglePasswordsCsv.serialize(
            listOf(ProtonItem(name = "Plain", username = "u", password = "p"))
        )
        assertEquals("name,url,username,password\nPlain,,u,p\n", csv)
    }

    @Test
    fun headerlessFallbackAndBom() {
        // A headerless 4-column file in the canonical order + the BOM.
        val items = GooglePasswordsCsv.parse(
            "\uFEFFName,URL,User,Pass\nX,https://x.example,ux,px\n"
        )
        // No recognizable header row → the positional order stands, every
        // row (including "Name,URL,User,Pass") is data — the headerless
        // shape is the user's promise.
        assertEquals(2, items.size)
        assertEquals("X", items[1].name)
        assertEquals("px", items[1].password)
    }

    @Test
    fun caseInsensitiveHeaderAndExtraColumns() {
        val items = GooglePasswordsCsv.parse(
            "Name,URL,Username,Password,Note\n" +
                "Y,https://y.example,uy,py,keep-out\n"
        )
        assertEquals(1, items.size)
        assertEquals("Y", items[0].name)
        assertEquals("py", items[0].password)
    }

    /** The adoption path: the parsed items ride the standard envelope —
     *  the same JSON round-trip every other import lands in. */
    @Test
    fun csvItemsAdoptIntoTheEnvelope() {
        val env = Envelope(items = GooglePasswordsCsv.parse(export).toMutableList())
        val again = Envelope.fromJson(env.toJsonObject().toString())
        // The envelope JSON decode sorts by displayName — compare as sets.
        assertEquals(env.items.map { it.name }.toSet(), again.items.map { it.name }.toSet())
        assertEquals("pw1", again.items.first { it.name == "GitHub" }.password)
    }

    @Test
    fun emptyInputParsesEmpty() {
        assertTrue(GooglePasswordsCsv.parse("").isEmpty())
        assertEquals("name,url,username,password\n", GooglePasswordsCsv.serialize(emptyList()))
    }
}
