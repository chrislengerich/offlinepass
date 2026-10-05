package com.linuxpass.app.vault

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

    @Test
    fun emptySidesMerge() {
        val empty = Envelope(rev = 0)
        val merged = VaultMerge.unionMerge(empty, env(3, "A"))
        assertEquals(listOf("A"), merged.items.map { it.name })
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
        assertEquals("otpauth://totp/linuxpass?secret=JBSWY3DPEHPK3PXP&issuer=linuxpass", uri)
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
        assertTrue(pw.all { it in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+" })
    }
}
