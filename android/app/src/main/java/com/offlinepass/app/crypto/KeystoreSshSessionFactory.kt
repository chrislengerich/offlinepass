package com.offlinepass.app.crypto

import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.offlinepass.app.vault.VaultSession
import org.eclipse.jgit.transport.RemoteSession
import org.eclipse.jgit.transport.SshSessionFactory
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * JGit SSH transport over the mwiede JSch fork, with the git identity
 * living non-exportably in Android Keystore ([SshKeyManager]).
 *
 * JGit 7 dropped its JSch transport; this is the minimal replacement:
 * a [SshSessionFactory] producing a [RemoteSession] whose exec() wraps a
 * JSch exec channel as a [Process] (exactly the contract JGit's push/fetch
 * drive). The SSH userauth exchange is signed by the Keystore key —
 * screenlock-gated, so syncs take place after a biometric/device-credential
 * interaction (the key's 60s validity window covers the whole sync).
 *
 * Host-key policy: accept-new (TOFU) — the first connect pins GitHub's
 * host key; a changed host key fails loudly, as it should.
 */
object KeystoreSshSessionFactory {

    /** Diagnostics from the most recent SSH session (handshake failure or
     *  exec stderr tail) — surfaced in sync failure messages because
     *  JGit's "remote hung up unexpectedly" hides GitHub's actual reason. */
    @Volatile var lastSessionDiagnostics: String = ""

    fun register() {
        if (SshSessionFactory.getInstance() !is Factory) SshSessionFactory.setInstance(Factory())
        installJschLogger()
    }

    /** Routes JSch's own logs into the app's log channel (the tag "JSch").
     *  The default logger suppresses the DEBUG-level userauth details —
     *  exactly the lines that say WHERE a disconnect happened (the offer,
     *  the preauth probe, the signature). The fork's levels: 0=DEBUG,
     *  1=INFO, 2=WARN, 3=ERROR. */
    private fun installJschLogger() {
        JSch.setLogger(object : com.jcraft.jsch.Logger {
            override fun isEnabled(level: Int): Boolean = true
            override fun log(level: Int, message: String) {
                when (level) {
                    com.jcraft.jsch.Logger.DEBUG -> android.util.Log.d("JSch", message)
                    com.jcraft.jsch.Logger.INFO -> android.util.Log.i("JSch", message)
                    com.jcraft.jsch.Logger.WARN -> android.util.Log.w("JSch", message)
                    else -> android.util.Log.e("JSch", message)
                }
            }
        })
    }

    class Factory : SshSessionFactory() {
        override fun getType(): String = "offlinepass-jsch"

        override fun getSession(
            uri: org.eclipse.jgit.transport.URIish,
            credentialsProvider: org.eclipse.jgit.transport.CredentialsProvider?,
            fs: org.eclipse.jgit.util.FS?,
            tms: Int
        ): RemoteSession {
            // The active SSH identity: screenlock keystore key or the
            // YubiKey auth subkey (OpenKeyChain) — chosen by the enrolled
            // mode. VaultSession builds it; null → nothing enrolled.
            val identity = VaultSession.sshIdentityProvider()
                ?: throw IOException(
                    VaultSession.sshIdentityUnavailable
                        ?: "No SSH identity enrolled (Setup)")
            val port = if (uri.port > 0) uri.port else 22
            val user = uri.user ?: "git"
            val host = uri.host
            val offerFp = "SHA256:" + java.util.Base64.getEncoder().withoutPadding()
                .encodeToString(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(identity.publicKeyBlob))
            android.util.Log.i("SshSync", "offering key to $user@$host:$port - " +
                "fp=$offerFp, alg=" + identity.getAlgName() + ", blob=" + identity.publicKeyBlob.size + "B")
            val jsch = JSch()
            jsch.addIdentity(identity, null)

            val session = jsch.getSession(user, host, port)
            session.setConfig("StrictHostKeyChecking", "accept-new")
            session.timeout = tms * 1000
            try {
                session.connect(tms * 1000)
            } catch (e: Exception) {
                // Handshake failures (auth refused, network) die BEFORE the
                // exec channel exists — record them here.
                lastSessionDiagnostics = "SSH handshake failed: ${e.message}"
                android.util.Log.w("SshSync",
                    "handshake failed: ${e.javaClass.simpleName}: ${e.message} " +
                        "(offered fp=SHA256:" + java.util.Base64.getEncoder()
                            .withoutPadding()
                            .encodeToString(java.security.MessageDigest.getInstance("SHA-256")
                                .digest(identity.publicKeyBlob)) + ")")
                throw e
            }
            return JschRemoteSession(session)
        }
    }

    /** RemoteSession over a connected JSch session: exec() wraps an exec
     *  channel in a Process for JGit's fetch/push packet machinery. */
    class JschRemoteSession(private val session: Session) : RemoteSession {
        override fun exec(commandName: String, timeout: Int): java.lang.Process {
            val channel = session.openChannel("exec") as ChannelExec
            channel.setCommand(commandName)
            channel.setInputStream(null) // null → getOutputStream() feeds remote stdin
            return JschProcess(channel, timeout)
        }

        override fun disconnect() {
            session.disconnect()
        }
    }

    /** Process adapter over a connected exec channel: JGit writes the fetch
     *  negotiation/pack to stdin and reads the sideband from stdout/stderr. */
    class JschProcess(private val channel: ChannelExec, timeout: Int) : java.lang.Process() {
        private val stdout: InputStream = channel.inputStream
        private val stderr: InputStream = channel.errStream
        private val stdin: OutputStream = channel.outputStream
        private val stderrCollector = StringBuilder()
        private val collectorDone = java.util.concurrent.CountDownLatch(1)

        init {
            channel.connect(timeout * 1000)
            Thread {
                try {
                    val buf = ByteArray(4096)
                    while (!channel.isClosed && !channel.isEOF) {
                        val n = stderr.read(buf)
                        if (n <= 0) break
                        synchronized(stderrCollector) {
                            if (stderrCollector.length < 4096) stderrCollector.append(String(buf, 0, n))
                        }
                    }
                } catch (_: Exception) {
                } finally {
                    collectorDone.countDown()
                }
            }.apply { isDaemon = true; start() }
        }

        /** Bounded stderr tail + exit status — surfaces GitHub's actual
         *  rejection reason (read-only deploy key, permissions, etc.). */
        fun diagnostics(): String = runCatching {
            collectorDone.await(2, java.util.concurrent.TimeUnit.SECONDS)
        }.let {
            synchronized(stderrCollector) {
                val tail = stderrCollector.toString().trim().take(800)
                val exit = if (channel.isClosed) "exit=${channel.exitStatus}" else "still-running"
                if (tail.isEmpty()) "[$exit, no stderr]" else "[$exit, stderr: $tail]"
            }
        }

        override fun getOutputStream(): OutputStream = stdin
        override fun getInputStream(): InputStream = stdout
        override fun getErrorStream(): InputStream = stderr

        override fun waitFor(): Int {
            // The channel closes when the remote command exits.
            while (!channel.isClosed) Thread.sleep(50)
            return exitValue()
        }

        override fun waitFor(timeout: Long, unit: java.util.concurrent.TimeUnit): Boolean {
            val deadline = System.currentTimeMillis() + unit.toMillis(timeout)
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(50)
            return channel.isClosed
        }

        override fun exitValue(): Int =
            if (channel.isClosed) channel.exitStatus
            else throw IllegalThreadStateException("remote command still running")

        override fun destroy() {
            channel.disconnect()
        }

        init {
            // When the exec channel closes, publish its stderr tail + exit
            // status as the session diagnostics.
            Thread {
                collectorDone.await()
                val tail = synchronized(stderrCollector) { stderrCollector.toString().trim().take(800) }
                lastSessionDiagnostics = "exec exit=${channel.exitStatus}" +
                    (if (tail.isNotEmpty()) ", stderr: $tail" else "")
            }.apply { isDaemon = true; start() }
        }
    }

    private fun sshString(b: ByteArray): ByteArray {
        val out = ByteArray(4 + b.size)
        var i = b.size
        out[3] = (i and 0xFF).toByte(); i = i shr 8
        out[2] = (i and 0xFF).toByte(); i = i shr 8
        out[1] = (i and 0xFF).toByte(); i = i shr 8
        out[0] = (i and 0xFF).toByte()
        b.copyInto(out, 4)
        return out
    }
}
