package com.offlinepass.app.crypto

import com.jcraft.jsch.JSch
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.ServerSocket
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey

/**
 * The REAL SSH handshake without network or hardware: a local Apache MINA
 * sshd server (publickey-only, authorized = the enrolled line) against the
 * production JSch client carrying [YubiKeySshIdentity] with the simulated
 * card (raw RSA over the PKCS#1 block — the OpenPGP AUT-slot model).
 *
 * This exercises what GitHub will actually run: algorithm negotiation,
 * the public-key offer (the enrolled blob must match), the signature
 * request, our SSH wire framing, and the server-side verification.
 */
class SshHandshakeTest {

    private lateinit var server: SshServer
    private lateinit var enrolled: KeyPair
    private lateinit var enrolledLine: String
    private lateinit var modulusSize: IntWrapper

    class IntWrapper(var value: Int = 0)

    private fun sshString(b: ByteArray): ByteArray {
        val out = ByteArray(4 + b.size)
        out[0] = ((b.size ushr 24) and 0xFF).toByte()
        out[1] = ((b.size ushr 16) and 0xFF).toByte()
        out[2] = ((b.size ushr 8) and 0xFF).toByte()
        out[3] = (b.size and 0xFF).toByte()
        b.copyInto(out, 4)
        return out
    }

    /** The card: RAW RSA over the received PKCS#1 block (AUT slot). */
    private fun simulateCardSign(
        block: ByteArray,
        privateKey: java.security.PrivateKey,
    ): ByteArray {
        val c = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding")
        c.init(javax.crypto.Cipher.DECRYPT_MODE, privateKey)
        return c.doFinal(block)
    }

    private fun lineFor(kp: KeyPair): Pair<String, Int> {
        val pub = kp.public as RSAPublicKey
        val e = pub.publicExponent.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        val n = pub.modulus.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        // Canonical mpints: the leading 0x00 sign byte when the high bit is
        // set (RFC 4251 §5) — without it strict parsers read n as negative.
        fun mpint(v: ByteArray) = if ((v[0].toInt() and 0x80) != 0) byteArrayOf(0) + v else v
        val blob = sshString("ssh-rsa".toByteArray()) + sshString(mpint(e)) + sshString(mpint(n))
        return "ssh-rsa " + java.util.Base64.getEncoder().encodeToString(blob) to
            (pub.modulus.bitLength() + 7) / 8
    }

    @Before
    fun startServer() {
        enrolled = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val (line, modSize) = lineFor(enrolled)
        enrolledLine = line
        modulusSize = IntWrapper(modSize)

        server = SshServer.setUpDefaultServer()
        server.port = ServerSocket(0).use { it.localPort }
        server.keyPairProvider = org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider()
        server.userAuthFactories = listOf(UserAuthPublicKeyFactory.INSTANCE)
        // Publickey-only; the authorized key is EXACTLY the enrolled line's.
        val enrolledPub = enrolled.public as RSAPublicKey
        server.publickeyAuthenticator = PublickeyAuthenticator { user, key, _ ->
            val ok = key is RSAPublicKey &&
                key.modulus == enrolledPub.modulus &&
                key.publicExponent == enrolledPub.publicExponent
            val line = "SSH-AUTH: user=$user keyType=${key.algorithm}(${key.format}) " +
                "bits=${(key as? RSAPublicKey)?.modulus?.bitLength()} accepted=$ok"
            System.err.println(line)
            runCatching { java.io.File("/tmp/opencode/ssh-auth-debug.log").appendText(line + "\n") }
            ok
        }
        server.start()
    }

    @After
    fun stopServer() {
        server.stop(true)
    }

    private fun identityWith(signer: (suspend (ByteArray) -> ByteArray)?): YubiKeySshIdentity =
        YubiKeySshIdentity(
            client = null,
            // 0xF9C2099733B184AD unsigned — Kotlin hex literals cannot exceed Long.MAX
            authSubkeyId = -0x63DF668CC4E7B53L,
            publicKeyLine = enrolledLine,
            interaction = { null },
            yubiKitSigner = signer)

    private fun connect(identity: YubiKeySshIdentity) {
        val logFile = java.io.File("/tmp/opencode/ssh-auth-debug.log")
        com.jcraft.jsch.JSch.setLogger(object : com.jcraft.jsch.Logger {
            override fun isEnabled(level: Int): Boolean = true
            override fun log(level: Int, message: String) {
                System.err.println("JSCH[$level] $message")
            }
        })
        val jsch = JSch()
        jsch.addIdentity(identity, null)
        val session = jsch.getSession("git", "localhost", server.port)
        session.setConfig("StrictHostKeyChecking", "no")
        session.timeout = 10000
        try {
            session.connect(10000)
        } finally {
            session.disconnect()
        }
    }

    @Test
    fun simulatedCardSignsASuccessfulHandshake() {
        val identity = identityWith { payload ->
            // The client side sends the full PKCS#1 block; the card signs raw.
            assertTrue("payload must be the padded block", payload.size == modulusSize.value &&
                payload[0] == 0x00.toByte() && payload[1] == 0x01.toByte())
            simulateCardSign(payload, enrolled.private)
        }
        connect(identity)
    }

    @Test
    fun aGarbageSignatureIsRejected() {
        val identity = identityWith { payload ->
            java.security.SecureRandom().run {
                val junk = ByteArray(modulusSize.value); nextBytes(junk); junk
            }
        }
        try {
            connect(identity)
            throw AssertionError("the handshake must NOT succeed with a garbage signature")
        } catch (expected: Exception) {
            // JSch reports the auth failure as an exception — any of them is
            // fine as long as the connect did not succeed.
        }
    }

    @Test
    fun anUnenrolledKeyIsRejected() {
        val stranger = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val (strangerLine, _) = lineFor(stranger)
        val identity = YubiKeySshIdentity(
            client = null, authSubkeyId = 1L, publicKeyLine = strangerLine,
            interaction = { null },
            yubiKitSigner = { payload -> simulateCardSign(payload, stranger.private) })
        try {
            connect(identity)
            throw AssertionError("the handshake must NOT succeed with an unenrolled key")
        } catch (expected: Exception) {
        }
    }
}
