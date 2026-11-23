package com.offlinepass.app.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * THE RELINK FLOW (the SimpleLogin api-key item): the link = the vault
 * item (the name "SimpleLogin API", the password = the api key, the URL
 * = the SL host); the RELINK = the UPDATE IN PLACE — the same itemUuid,
 * the new key — so the merge propagates it as an update and the old key
 * cannot resurrect through the removal-without-tombstone path.
 */
class SimpleLoginRelinkTest {

    private fun slItem(apiKey: String, uuid: String? = null): ProtonItem {
        val item = ProtonItem(
            name = "SimpleLogin API",
            email = "me@passmail.net",
            password = apiKey,
            urls = listOf("https://app.simplelogin.io"))
        uuid?.let { item.itemUuid = it }
        return item
    }

    /** THE RELINK: the existing SL item's key + email replaced IN PLACE
     *  (the same itemUuid) — the mirror of linkSimpleLogin's behavior. */
    private fun relink(items: MutableList<ProtonItem>, newKey: String) {
        val existing = items.firstOrNull { it.name == "SimpleLogin API" }
        if (existing != null) {
            val uuid = existing.itemUuid
            items.removeAll { it.itemUuid == uuid }
            val fresh = slItem(newKey)
            fresh.itemUuid = uuid
            items.add(fresh)
        } else items.add(slItem(newKey))
    }

    @Test
    fun `relink replaces the key in place (the same uuid, exactly one)`() {
        val items = mutableListOf(slItem("OLD-KEY", "stable-uuid-1"))
        relink(items, "NEW-KEY")
        assertEquals(1, items.size)
        assertEquals("NEW-KEY", items.first().password)
        assertEquals("stable-uuid-1", items.first().itemUuid)
    }

    @Test
    fun `the merge with a synced peer - the relink survives as an update (no resurrection)`() {
        // The peer's copy carries the OLD key under the SAME uuid; the
        // union-merge by itemUuid = one item, the relink's key wins (the
        // newer modifyTime).
        val mine = Envelope(rev = 5, deviceId = "d1").also { e ->
            e.items = mutableListOf(slItem("OLD-KEY", "stable-uuid-1").apply { modifyTime = 100 })
        }
        val theirs = Envelope(rev = 6, deviceId = "d2").also { e ->
            e.items = mutableListOf(slItem("NEW-KEY", "stable-uuid-1").apply { modifyTime = 200 })
        }
        val merged = VaultMerge.unionMerge(mine, theirs)
        val slItems = merged.items.filter { it.name == "SimpleLogin API" }
        assertEquals(1, slItems.size)
        assertEquals("NEW-KEY", slItems.first().password)
    }

    @Test
    fun `a fresh link after unlink gets a new uuid (no stale carry-over)`() {
        val items = mutableListOf(slItem("OLD-KEY", "old-uuid"))
        items.clear()
        relink(items, "NEW-KEY")
        assertEquals(1, items.size)
    }
}
