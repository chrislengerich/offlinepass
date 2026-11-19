package com.offlinepass.app.crypto

/**
 * The GitHub-.keys enrollment's pure logic: derive the username from the
 * remote, match a card signature against candidate SSH lines, and derive
 * the OpenPGP key id from the card's fingerprint.
 *
 * The match is a POSITIVE PROOF: the card signs a nonce (one touch) and
 * the line whose public key verifies that signature is, provably, the key
 * the card will sign with — the wrong-subkey class of enrollment bug is
 * structurally impossible. An SSH blob cannot be mapped back to an OpenPGP
 * fingerprint (imported cards expose only fingerprints), so the key id
 * comes from the card, and the line from the verified match.
 */
object GithubKeysEnrollment {

    /** The GitHub username from a remote URL:
     *  git@github.com:USER/repo.git or https://github.com/USER/... */
    fun parseUsername(remote: String): String? {
        val trimmed = remote.trim()
        val m = Regex("git@github\\.com:([^/]+)/").find(trimmed)
        if (m != null) return m.groupValues[1]
        val m2 = Regex("https://github\\.com/([^/]+)(/|$)").find(trimmed)
        return m2?.groupValues?.get(1)
    }

    /** The v4 fingerprint's low 8 bytes = the OpenPGP key id (unsigned). */
    fun keyIdFromFingerprint(fp: ByteArray): Long {
        require(fp.size >= 20) { "a fingerprint needs 20 bytes" }
        return (12 until 20).fold(0L) { acc, k ->
            (acc shl 8) or (fp[k].toLong() and 0xFF)
        }
    }

    /** The candidate line whose public key verifies the card's signature
     *  over [nonce], or null when nothing matches. RSA cards answer with
     *  the raw RSA result over the SHA-256 DigestInfo; EC cards answer
     *  with the DER ECDSA over the raw digest — the verifier follows the
     *  LINE's algorithm, so a mixed GitHub key list matches either. */
    fun match(lines: List<String>, nonce: ByteArray, rawSig: ByteArray): String? {
        for (line in lines) {
            val parsed = runCatching { PgpSshBridge.parsePublicKeyLine(line) }.getOrNull()
                ?: continue
            val verifyAlg = when (parsed.algorithm) {
                "ssh-rsa" -> "SHA256withRSA"
                "ecdsa-sha2-nistp256" -> "SHA256withECDSA"
                else -> continue
            }
            val pub = runCatching { PgpSshBridge.publicKeyFromLine(parsed) }.getOrNull()
                ?: continue
            val verifier = runCatching {
                java.security.Signature.getInstance(verifyAlg)
                    .apply { initVerify(pub); update(nonce) }
            }.getOrNull() ?: continue
            if (runCatching { verifier.verify(rawSig) }.getOrDefault(false)) return line
        }
        return null
    }

    // -- The live fetch + the full orchestration ------------------------------

    /** The live fetch: github.com/<user>.keys, filtered to key lines. */
    fun fetchKeyLines(username: String): List<String> =
        filterKeyLines(fetchKeysBody(username))

    fun filterKeyLines(body: String): List<String> =
        body.lines()
            .map { it.trim() }
            .filter {
                (it.startsWith("ssh-") || it.startsWith("ecdsa-") ||
                    it.startsWith("sk-")) &&
                    // A bare algorithm token ("ssh-rsa") is not a key line.
                    it.split(" ").size >= 2
            }

    private fun fetchKeysBody(username: String): String {
        val url = java.net.URL("https://github.com/$username.keys")
        val c = (url.openConnection() as java.net.HttpURLConnection).apply {
            connectTimeout = 10_000
            readTimeout = 10_000
            instanceFollowRedirects = true
        }
        try {
            if (c.responseCode != 200) {
                throw java.io.IOException(
                    "github.com/$username.keys returned HTTP ${c.responseCode}")
            }
            return c.inputStream.bufferedReader().readText()
        } finally {
            c.disconnect()
        }
    }

    /** The full enrollment orchestration with injected dependencies — the
     *  same flow the UI drives, fully stub-able in tests:
     *  fetch → the SLOT DISCOVERY (the AUT slot first — the dedicated
     *  auth key; a transport failure like the RSA-4096 0x6581 dead end
     *  or a match-miss falls through to the SIG slot) → the nonce proof
     *  (ONE touch per attempted slot) → the match → enroll WITH the
     *  matched slot. THE GITHUB INFO SELECTS THE SLOT — no user toggle:
     *  the enrolled line names the slot that signs the handshakes.
     *  Returns the user-facing status. */
    suspend fun enroll(
        remote: String,
        fetchLines: suspend (String) -> List<String>,
        cardIdentity: suspend (useAut: Boolean) -> Pair<Long, ByteArray>,
        cardSign: suspend (useAut: Boolean, nonce: ByteArray) -> ByteArray,
        enroll: (String, Long, String) -> Unit,
    ): String {
        val user = parseUsername(remote.trim())
            ?: return "The remote does not name a GitHub user — " +
                "enter git@github.com:<user>/<repo> first."
        val lines = try {
            fetchLines(user)
        } catch (e: Exception) {
            return "Fetching github.com/$user.keys failed: ${e.message}"
        }
        if (lines.isEmpty()) return "No SSH keys registered on GitHub for $user."
        val nonce = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        var lastError: String? = null
        var anySig = false
        for ((useAut, slotName) in listOf(true to "AUTH", false to "SIGNATURE")) {
            val (keyId, fingerprint) = try {
                cardIdentity(useAut)
            } catch (e: Exception) {
                lastError = e.message
                continue
            }
            val rawSig = try {
                cardSign(useAut, nonce)
            } catch (e: Exception) {
                lastError = e.message
                continue
            }
            anySig = true
            val matched = match(lines, nonce, rawSig)
            if (matched != null) {
                enroll(matched, keyId, slotName)
                return "Enrolled the $slotName-slot key 0x%016X (verified against " +
                    "$user's GitHub keys). The transport follows the enrolled key.".format(keyId)
            }
        }
        // Both slots exhausted: a GitHub-coverage gap or a card failure —
        // name which.
        return if (!anySig && lastError != null) "The card could not prove a key: $lastError"
        else "No GitHub key of $user matches this security key — " +
            "add the key's SSH line at github.com/settings/keys " +
            "(New SSH key → Authentication key), then re-run Enroll."
    }
}
