package com.offlinepass.app.vault

import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** convertRemote: scheme conversion between sync-auth modes must never
 *  discard the user's typed text (the old handlers replaced the field). */
@RunWith(RobolectricTestRunner::class)
class ConvertRemoteTest {

    private val sshForm = "git@github.com:chrislengerich/offlinepass-state.git"
    private val httpsForm = "https://github.com/chrislengerich/offlinepass-state.git"

    @Test
    fun sshToPatAndBackPreservesThePath() {
        assertEquals(httpsForm, VaultSession.convertRemote(sshForm, "pat"))
        assertEquals(sshForm, VaultSession.convertRemote(httpsForm, "ssh"))
    }

    @Test
    fun alreadyCorrectFormIsUntouched() {
        assertEquals(sshForm, VaultSession.convertRemote(sshForm, "ssh"))
        assertEquals(httpsForm, VaultSession.convertRemote(httpsForm, "pat"))
        // Both ssh variants count as "already correct" for ssh modes.
        assertEquals("ssh://github.com/o/r", VaultSession.convertRemote("ssh://github.com/o/r", "ssh"))
    }

    @Test
    fun bareOwnerRepoGetsThePrefixPrepended() {
        assertEquals("git@github.com:owner/repo",
            VaultSession.convertRemote("owner/repo", "ssh"))
        assertEquals("https://github.com/owner/repo",
            VaultSession.convertRemote("owner/repo", "pat"))
    }

    @Test
    fun hostOnlyAndBlankGetTheDefaults() {
        assertEquals("git@github.com:", VaultSession.convertRemote("github.com", "ssh"))
        assertEquals("https://github.com/", VaultSession.convertRemote("github.com", "pat"))
        assertEquals("git@github.com:", VaultSession.convertRemote("", "ssh"))
        assertEquals("https://github.com/", VaultSession.convertRemote("", "pat"))
    }

    @Test
    fun slashFormAfterGitAtPassesThrough() {
        // The user typed it with slashes — it stays as typed on the ssh modes.
        assertEquals("git@github.com/owner/repo",
            VaultSession.convertRemote("git@github.com/owner/repo", "ssh"))
    }
}
