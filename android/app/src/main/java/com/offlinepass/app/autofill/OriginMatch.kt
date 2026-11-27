package com.offlinepass.app.autofill

import com.offlinepass.app.vault.ProtonItem

/**
 * THE ORIGIN MATCHER — the precise URL→item rule for the fill sheet's
 * ranking. The old `url.contains(...)` substring was loose in both
 * directions: `icml.cc` "matched" `xicml.cc` (no dot boundary), and the
 * browser-package check was dead weight (no item URL contains
 * `com.android.chrome` — the appPackage in a web fill is the BROWSER's).
 *
 * The rules (the standard PM heuristics):
 *  - WEB: same host, or one host is a DOT-BOUNDARY suffix of the other
 *    (login.icml.cc ↔ icml.cc match; xicml.cc ↔ icml.cc do not).
 *  - NATIVE APP: the reverse-domain convention — the URL's host reversed
 *    (proton.me → me.proton) prefixes the app's package
 *    (me.proton.android.pass). The dot boundary again: com.bank.app
 *    matches bank.com, com.banky.app does not.
 */
internal object OriginMatch {

    /** The URL's host, lowercased and www-stripped (null for garbage). A
     *  scheme is assumed when absent (the vault's URLs often omit it). */
    fun hostOf(url: String): String? = runCatching {
        val t = url.trim()
        val withScheme = if ("://" in t) t else "https://$t"
        java.net.URI(withScheme).host?.lowercase()?.removePrefix("www.")
    }.getOrNull()

    fun hostMatches(a: String, b: String): Boolean =
        a == b || a.endsWith(".$b") || b.endsWith(".$a")

    fun packageMatches(host: String, appPackage: String): Boolean {
        val rev = host.split(".").reversed().joinToString(".")
        return appPackage == rev || appPackage.startsWith("$rev.")
    }

    /** The ranking tier: the web-domain match (2) beats the native-app
     *  match (1) beats no match (0) — the same tiers the old contains()
     *  ranking used, now with precise predicates. */
    fun rank(item: ProtonItem, webDomain: String?, appPackage: String): Int {
        if (webDomain != null) {
            val d = webDomain.lowercase().removePrefix("www.")
            if (item.urls.any { u -> hostOf(u)?.let { hostMatches(it, d) } == true }) return 2
        }
        if (item.urls.any { u -> hostOf(u)?.let { packageMatches(it, appPackage) } == true }) return 1
        return 0
    }
}
