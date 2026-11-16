package com.offlinepass.app.vault

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * pinCachingSigner: the PIN is prompted once per session and cached ONLY
 * after a successful sign. A wrong PIN (the sign throws) must NOT be
 * cached — the next invocation re-prompts (the card's attempts-remaining
 * message surfaces through the exception) instead of silently failing
 * every retry with the poisoned value.
 */
class PinCachingSignerTest {

    private class WrongPin : java.io.IOException("Wrong PIN — 2 attempt(s) remaining")

    @Test
    fun wrongPinIsNotCachedTheNextAttemptRePrompts() = kotlinx.coroutines.runBlocking {
        val prompts = mutableListOf<String>()
        val pinsSeenByCard = mutableListOf<String>()
        var failNext = true
        val signer = VaultSession.pinCachingSigner(
            prompt = {
                val pin = if (failNext) "111111" else "222222"
                prompts += pin
                pin.toCharArray()
            },
            sign = { pin, _ ->
                pinsSeenByCard += pin.concatToString()
                if (failNext) throw WrongPin()
                byteArrayOf(1)
            })

        // 1st call: the wrong PIN → the sign throws, NOTHING is cached.
        try {
            signer("payload".toByteArray())
            throw AssertionError("the wrong-PIN sign must throw")
        } catch (e: java.io.IOException) {
            assertTrue("message must name the attempts", e.message!!.contains("2 attempt"))
        }
        assertEquals(listOf("111111"), prompts)
        assertEquals(listOf("111111"), pinsSeenByCard)

        // 2nd call: RE-PROMPTED (the wrong PIN was not cached); succeeds.
        failNext = false
        assertArrayEquals(byteArrayOf(1), signer("payload".toByteArray()))
        assertEquals(listOf("111111", "222222"), prompts)
        assertEquals(listOf("111111", "222222"), pinsSeenByCard)

        // 3rd call: the GOOD pin is cached now — no further prompt.
        signer("again".toByteArray())
        assertEquals(listOf("111111", "222222"), prompts)
        assertEquals(listOf("111111", "222222", "222222"), pinsSeenByCard)
    }

    @Test
    fun promptReturningNullMeansCancelled() = kotlinx.coroutines.runBlocking {
        val signer = VaultSession.pinCachingSigner(prompt = { null }, sign = { _, _ -> byteArrayOf(0) })
        try {
            signer("x".toByteArray())
            throw AssertionError("a cancelled prompt must throw")
        } catch (e: java.io.IOException) {
            assertEquals("OpenPGP PIN cancelled", e.message)
        }
    }
}
