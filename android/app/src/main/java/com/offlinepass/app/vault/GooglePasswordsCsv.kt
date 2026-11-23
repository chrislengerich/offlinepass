package com.offlinepass.app.vault

/**
 * The GOOGLE PASSWORDS CSV: the four-column format (`name,url,username,
 * password`) that Google Password Manager — Android's export and Chrome's
 * both — writes, and that Chrome's import accepts back. The second foreign
 * format beside the Proton export (the same role, the same flows).
 *
 * THE LOSSY RULE: the Google CSV has NO note, TOTP, multi-URL, passkey or
 * alias columns — an import drops those (nothing to import), and an export
 * carries only name/url/username/password. The callers say so in their
 * status lines.
 */
object GooglePasswordsCsv {

    /** The canonical header — exactly what Chrome/GPM writes. */
    const val HEADER = "name,url,username,password"

    /**
     * THE IMPORT: the picked Google export → login items. Lenient on the
     * header: the canonical four by name (case-insensitive, extra columns
     * ignored, the BOM tolerated), falling back to the positional
     * `name,url,username,password` order when no header row is present.
     */
    fun parse(raw: String): List<ProtonItem> {
        val rows = parseRows(raw)
        if (rows.isEmpty()) return emptyList()

        // The header row: the first row mentioning `username` AND `password`
        // as whole cells (a data row would need a user literally named
        // "username" with the password "password" — accepted risk). Without
        // one, the canonical positional order stands.
        val header = rows.first().map { it.trim().trimStart('\uFEFF').lowercase() } // the BOM tolerated
        val idx: Map<String, Int>?
        val dataRows: List<List<String>>
        if (header.contains("username") && header.contains("password")) {
            idx = mapOf(
                "name" to header.indexOf("name"),
                "url" to header.indexOf("url"),
                "username" to header.indexOf("username"),
                "password" to header.indexOf("password")
            )
            dataRows = rows.drop(1)
        } else {
            idx = mapOf("name" to 0, "url" to 1, "username" to 2, "password" to 3)
            dataRows = rows
        }

        return dataRows.map { cells ->
            fun col(key: String): String =
                idx[key]?.takeIf { it >= 0 && it < cells.size }?.let { cells[it] } ?: ""
            val url = col("url").trim()
            ProtonItem(
                name = col("name"),
                username = col("username"),
                password = col("password"),
                urls = if (url.isBlank()) emptyList() else listOf(url)
            )
        }
    }

    /**
     * THE EXPORT: the items → the Google CSV text (the header + one row per
     * item). Only the four Google columns — the caller warns about the
     * dropped note/TOTP/extra-URL material. Quoting per RFC-4180: a field
     * with a comma, quote or newline rides in quotes, quotes doubled.
     */
    fun serialize(items: List<ProtonItem>): String {
        val sb = StringBuilder(HEADER).append('\n')
        items.forEach { it ->
            sb.append(csvField(it.name)).append(',')
                .append(csvField(it.urls.firstOrNull() ?: "")).append(',')
                .append(csvField(it.username.ifBlank { it.email })).append(',')
                .append(csvField(it.password))
            sb.append('\n')
        }
        return sb.toString()
    }

    /** RFC-4180 field quoting: quote only when the value needs it. */
    private fun csvField(value: String): String {
        if (!value.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) return value
        return "\"" + value.replace("\"", "\"\"") + "\""
    }

    /** THE RFC-4180 ROW READER: quoted fields (with embedded commas,
     *  newlines and `""` escapes) handled — passwords routinely contain
     *  commas, so the naive `split(",")` loses data. */
    private fun parseRows(raw: String): List<List<String>> {
        val rows = mutableListOf<MutableList<String>>()
        val row = mutableListOf<String>()
        val field = StringBuilder()
        var inQuotes = false
        var i = 0
        val n = raw.length
        var anyField = false
        while (i < n) {
            val c = raw[i]
            when {
                inQuotes -> when {
                    c == '"' -> {
                        if (i + 1 < n && raw[i + 1] == '"') { field.append('"'); i += 2 }
                        else { inQuotes = false; i += 1 }
                    }
                    else -> { field.append(c); i += 1 }
                }
                c == '"' -> {
                    inQuotes = true
                    anyField = true
                    i += 1
                }
                c == ',' -> {
                    row.add(field.toString()); field.setLength(0); anyField = true; i += 1
                }
                c == '\r' -> i += 1
                c == '\n' -> {
                    if (anyField || field.isNotEmpty()) {
                        row.add(field.toString()); field.setLength(0)
                        rows.add(row.toMutableList()); row.clear(); anyField = false
                    }
                    i += 1
                }
                else -> { field.append(c); anyField = true; i += 1 }
            }
        }
        if (anyField || field.isNotEmpty()) {
            row.add(field.toString())
            rows.add(row)
        }
        return rows
    }
}
