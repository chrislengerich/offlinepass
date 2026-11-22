package com.offlinepass.app.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class EnvelopeCodecTest {

    private val sample = """[{"itemId":"i1","shareId":"local","data":{"type":"login",
        "metadata":{"name":"GitHub","itemUuid":"u1"},"content":{"itemEmail":"","itemUsername":"ko",
        "password":"pw1","urls":["https://github.com"],"totpUri":"","passkeys":[]}},"state":1}]"""

    @Test
    fun roundTripListShape() {
        val env = Envelope.fromJson(sample)
        assertEquals(1, env.items.size)
        assertEquals("GitHub", env.items[0].name)
        assertEquals("ko", env.items[0].username)
        assertEquals("pw1", env.items[0].password)
        val again = Envelope.fromJson(env.toJsonObject().toString())
        assertEquals(env.items, again.items)
    }

    @Test
    fun unknownFieldsPreserved() {
        val env = Envelope.fromJson("""{"customThing":"keep-me","vaults":{"local":{"items":[]}}}""")
        assertEquals("keep-me", env.extraFields["customThing"])
        val out = env.toJsonObject()
        assertEquals("keep-me", out.getString("customThing"))
    }

    @Test
    fun revBumpsAndDeviceIdStable() {
        val env = Envelope.fromJson("""{"rev":5,"deviceId":"d1","vaults":{"local":{"items":[]}}}""")
        assertEquals(5, env.rev)
        assertEquals("d1", env.deviceId)
        env.rev += 1
        assertEquals(6, Envelope.fromJson(env.toJsonObject().toString()).rev)
    }

    @Test
    fun vaultsDictShape() {
        val env = Envelope.fromJson("""{"vaults":{"local":{"items":[{"itemId":"x","data":{"metadata":{"name":"A"},"content":{}}}]}}}""")
        assertEquals(1, env.items.size)
        assertEquals("A", env.items[0].displayName)
    }
}

@RunWith(RobolectricTestRunner::class)
class MergeTest {

    private fun env(rev: Long, vararg names: String) = Envelope(
        rev = rev,
        deviceId = "d",
        items = names.map { n -> ProtonItem(name = n, itemUuid = "u-$n", password = "pw-$n") }.toMutableList()
    )

    @Test
    fun unionKeepsBothSides() {
        val merged = VaultMerge.unionMerge(env(1, "A", "B"), env(2, "B", "C"))
        assertEquals(setOf("A", "B", "C"), merged.items.map { it.name }.toSet())
    }

    @Test
    fun tombstoneSurvivesSync() {
        val local = env(2, "A", "B")
        local.deletedItemUuids.add("u-B")
        val merged = VaultMerge.unionMerge(local, env(1, "A", "B", "C"))
        assertEquals(setOf("A", "C"), merged.items.map { it.name }.toSet())
        assertTrue("u-B" in merged.deletedItemUuids)
    }

    @Test
    fun newerCopyWinsForSameUuid() {
        val mine = env(2, "A")
        val theirs = env(5, "A")
        // Same uuid "u-A" by construction; theirs is newer -> its password wins.
        val merged = VaultMerge.unionMerge(mine, theirs)
        assertEquals("pw-A", merged.items.first().password) // same value; assert single item
        assertEquals(1, merged.items.size)
    }

    /** THE MEASURED LOSS CASE: the locally-edited entry rides an envelope
     *  with a LOWER rev than the other side's — the stale copy must not
     *  overwrite the newer item (the github.com entry, rev 8-vs-9). */
    @Test
    fun newerItemModifyTimeInOlderEnvelopeWins() {
        val mine = env(7, "A")
        val theirs = env(9, "A")
        mine.items[0].modifyTime = 200
        theirs.items[0].modifyTime = 100
        theirs.items[0].password = "stale-remote"
        val merged = VaultMerge.unionMerge(mine, theirs)
        assertEquals("pw-A", merged.items.single().password)
    }

    @Test
    fun equalModifyTimesKeepNewerEnvelopeCopy() {
        val mine = env(7, "A")
        val theirs = env(9, "A")
        mine.items[0].modifyTime = 100
        theirs.items[0].modifyTime = 100
        mine.items[0].username = "mine"
        theirs.items[0].username = "theirs"
        val merged = VaultMerge.unionMerge(mine, theirs)
        assertEquals("theirs", merged.items.single().username)
    }

    @Test
    fun knownModifyTimeBeatsUnknown() {
        val mine = env(7, "A")
        val theirs = env(9, "A")
        mine.items[0].modifyTime = 0
        theirs.items[0].modifyTime = 123
        theirs.items[0].username = "theirs"
        val merged = VaultMerge.unionMerge(mine, theirs)
        assertEquals("theirs", merged.items.single().username)
    }

    @Test
    fun tombstoneBeatsNewerItem() {
        val local = env(2, "A")
        local.deletedItemUuids.add("u-A")
        val theirs = env(9, "A")
        theirs.items[0].modifyTime = 999
        val merged = VaultMerge.unionMerge(local, theirs)
        assertTrue(merged.items.isEmpty())
        assertTrue("u-A" in merged.deletedItemUuids)
    }

    @Test
    fun emptySidesMerge() {
        val empty = Envelope(rev = 0)
        val merged = VaultMerge.unionMerge(empty, env(3, "A"))
        assertEquals(listOf("A"), merged.items.map { it.name })
    }

    /** THE USB/QRFT IMPORT RULE: an imported (older) envelope never
     *  clobbers the current repo's items — the union keeps both sides,
     *  the per-item modifyTime decides same-uuid conflicts, and the
     *  merged rev is max+1 (a child commit on top, nothing rewritten).
     *  The recipient adoption split rides the same path: restore
     *  (no repo) adopts the file's recipients; a merge does not. */
    @Test
    fun importMergesWithoutOverwrite() {
        val current = env(9, "A", "B")
        current.items.first { it.name == "A" }.modifyTime = 300
        val imported = env(4, "A", "C")
        imported.items.first { it.name == "A" }.modifyTime = 100
        imported.items.first { it.name == "A" }.password = "older-import"
        val merged = VaultMerge.unionMerge(current, imported)
        assertEquals(setOf("A", "B", "C"), merged.items.map { it.name }.toSet())
        assertEquals("pw-A", merged.items.first { it.name == "A" }.password)
        assertEquals(10L, merged.rev)
    }
}

class TotpTest {

    @Test
    fun rfc6238Vectors() {
        // RFC 6238 SHA-1 test vector: secret "12345678901234567890", 8 digits.
        val uri = "otpauth://totp/rfc?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30"
        val (code59, _) = Totp.generate(uri, atTime = 59)
        assertEquals("94287082", code59)
        val (code1111111109, _) = Totp.generate(uri, atTime = 1111111109)
        assertEquals("07081804", code1111111109)
    }

    @Test
    fun rawSecretNormalized() {
        val uri = Totp.normalizeSecretInput("JBSW Y3DP EHPK 3PXP")
        assertEquals("otpauth://totp/offlinepass?secret=JBSWY3DPEHPK3PXP&issuer=offlinepass", uri)
    }

    @Test
    fun otpauthParsing() {
        val q = Totp.parseOtpauth("otpauth://totp/Service:user?secret=ABC234&digits=8&period=60&issuer=Service")
        assertEquals("ABC234", q.secret)
        assertEquals(8, q.digits)
        assertEquals(60, q.period)
        assertEquals("Service", q.issuer)
    }
}

@RunWith(RobolectricTestRunner::class)
class ImportPathTest {
    @Test
    fun plaintextProtonListImport() {
        val env = Envelope.parseImport("""[{"itemId":"i","data":{"metadata":{"name":"S"},"content":{"password":"p"}}}]""")
        assertEquals(1, env?.items?.size)
        assertEquals("S", env?.items?.get(0)?.displayName)
    }

    @Test
    fun plaintextVaultsImport() {
        val env = Envelope.parseImport("""{"version":"1.0","vaults":{"local":{"items":[]}}}""")
        assertEquals(0, env?.items?.size)
    }

    @Test
    fun pgpArmorIsNotPlaintext() {
        assertNull(Envelope.parseImport("-----BEGIN PGP MESSAGE-----\nxx\n"))
        assertNull(Envelope.parseImport(java.lang.StringBuilder("com.random.binary").toString()))
    }
}

class PasswordGenTest {
    @Test
    fun alphabetRespected() {
        val pw = PasswordGen.password(64)
        assertEquals(64, pw.length)
        assertTrue("the alphanumeric only (the default flavor)", pw.all { it.isLetterOrDigit() })
    }

    /** The autofill generate-chip's draw: the uniqueness across 100
     *  default-length draws (a duplicate = a broken RNG path — the chip
     *  hands this straight into a registration form). */
    @Test
    fun defaultDrawsAreUnique() {
        assertEquals(16, PasswordGen.password().length)
        val draws = (1..100).map { PasswordGen.password() }.toSet()
        assertEquals("no duplicates in 100 draws", 100, draws.size)
    }
}
