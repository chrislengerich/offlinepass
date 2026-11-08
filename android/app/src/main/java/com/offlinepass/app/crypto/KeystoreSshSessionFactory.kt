package com.offlinepass.app.crypto

import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import org.eclipse.jgit.transport.RemoteSession
import org.eclipse.jgit.transport.SshSessionFactory
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

    fun register() {
        if (SshSessionFactory.getInstance() !is Factory) SshSessionFactory.setInstance(Factory())
    }

    class Factory : SshSessionFactory() {
        override fun getType(): String = "offlinepass-jsch"

        override fun getSession(
            uri: org.eclipse.jgit.transport.URIish,
            credentialsProvider: org.eclipse.jgit.transport.CredentialsProvider?,
            fs: org.eclipse.jgit.util.FS?,
            tms: Int
        ): RemoteSession {
            val manager = SshKeyManager()
            val info = manager.ensureKeyPair()
            val jsch = JSch()
            jsch.addIdentity(object : com.jcraft.jsch.Identity {
                override fun getAlgName(): String = info.algorithm  // "ssh-rsa"
                override fun getName(): String = "offlinepass-android"
                override fun getPublicKeyBlob(): ByteArray = info.wireBlob
                override fun getSignature(data: ByteArray): ByteArray {
                    // The identity signs the auth data with the Keystore key;
                    // the SSH wire expects string(algorithm) + string(sig),
                    // with the modern rsa-sha2-256 algorithm name.
                    val sig = manager.newSigner()
                    sig.update(data)
                    val raw = sig.sign()
                    val wireAlg = if (info.algorithm == "Ed25519") "ssh-ed25519" else "rsa-sha2-256"
                    return sshString(wireAlg.toByteArray()) + sshString(raw)
                }
                override fun setPassphrase(passphrase: ByteArray?): Boolean = true
                override fun isEncrypted(): Boolean = false
                override fun clear() {}
            }, null)

            val port = if (uri.port > 0) uri.port else 22
            val user = uri.user ?: "git"
            val session = jsch.getSession(user, uri.host, port)
            session.setConfig("StrictHostKeyChecking", "accept-new")
            session.timeout = tms * 1000
            session.connect(tms * 1000)
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

        init {
            channel.connect(timeout * 1000)
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
