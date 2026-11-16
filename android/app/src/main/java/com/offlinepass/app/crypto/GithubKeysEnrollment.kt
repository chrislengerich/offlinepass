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
     *  over [nonce], or null when nothing matches. The signature is the
     *  raw RSA result over the SHA-256 DigestInfo of the nonce (the card's
     *  PSO:CDS output). RSA lines are candidates; non-RSA lines cannot
     *  verify an RSA signature and are skipped. */
    fun match(lines: List<String>, nonce: ByteArray, rawSig: ByteArray): String? {
        for (line in lines) {
            val parsed = runCatching { PgpSshBridge.parsePublicKeyLine(line) }.getOrNull()
                ?: continue
            if (parsed.algorithm != "ssh-rsa") continue
            val pub = runCatching { PgpSshBridge.publicKeyFromLine(parsed) }.getOrNull()
                ?: continue
            val verifier = runCatching {
                java.security.Signature.getInstance("SHA256withRSA")
                    .apply { initVerify(pub); update(nonce) }
            }.getOrNull() ?: continue
            if (runCatching { verifier.verify(rawSig) }.getOrDefault(false)) return line
        }
        return null
    }
}
