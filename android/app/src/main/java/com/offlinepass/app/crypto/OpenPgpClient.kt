package com.offlinepass.app.crypto

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.Parcelable
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.openintents.openpgp.IOpenPgpService2
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.resume

/**
 * Minimal client for the OpenPGP API that OpenKeychain serves.
 *
 * The protocol surface is vendored from the Apache-2.0 openpgp-api library
 * (Copyright 2014-2015 Dominik Schürmann): the [SERVICE_INTENT_2] binding, the
 * version-11 extras, and the pipe arrangement, where the caller hands the
 * service a read side for the input, asks the service to create the write side
 * of the output by pipe id, and blocks on the binder call until the result
 * Intent returns. Kept for this app: key lookup by email, multi-recipient
 * binary encryption, decrypt-verify, armored public-key export, and sign-key
 * picking.
 *
 * First use needs the owner's approval inside OpenKeychain (an
 * interaction-only result), which is why key lookup runs from the unlock /
 * settings flow, where a PendingIntent can be launched; after that approval,
 * encrypting to a public key needs no interaction.
 */
class OpenPgpClient(private val context: Context) : OpenPgpOps {

    companion object {
        private const val TAG = "OpenPgpClient"

        /** The action OpenKeychain's remote service binds on. */
        const val SERVICE_INTENT_2 = "org.openintents.openpgp.IOpenPgpService2"

        /** OpenKeychain's package name, named explicitly when binding. */
        const val OPENKEYCHAIN_PACKAGE = "org.sufficientlysecure.keychain"

        /** API version this client speaks. */
        const val API_VERSION = 11

        const val ACTION_ENCRYPT = "org.openintents.openpgp.action.ENCRYPT"
        const val ACTION_SIGN_AND_ENCRYPT = "org.openintents.openpgp.action.SIGN_AND_ENCRYPT"
        const val ACTION_DECRYPT_VERIFY = "org.openintents.openpgp.action.DECRYPT_VERIFY"
        const val ACTION_GET_KEY_IDS = "org.openintents.openpgp.action.GET_KEY_IDS"
        /** Retrieves the whole public key for [EXTRA_KEY_ID] into the output pipe. */
        const val ACTION_GET_KEY = "org.openintents.openpgp.action.GET_KEY"
        const val ACTION_GET_SIGN_KEY_ID = "org.openintents.openpgp.action.GET_SIGN_KEY_ID"
    /** Detached PGP signature; result extra `detached_signature` (armored bytes). */
    const val ACTION_DETACHED_SIGN = "org.openintents.openpgp.action.DETACHED_SIGN"
    /** OpenKeychain's error parcelable (id + message) on failure results. */
    const val RESULT_ERROR = "error"

        const val EXTRA_API_VERSION = "api_version"
        const val EXTRA_USER_IDS = "user_ids"
        const val EXTRA_KEY_IDS = "key_ids"
        const val EXTRA_KEY_ID = "key_id"
        const val EXTRA_SIGN_KEY_ID = "sign_key_id"
        const val EXTRA_PASSPHRASE = "passphrase"
        const val EXTRA_ORIGINAL_FILENAME = "original_filename"
        const val EXTRA_REQUEST_ASCII_ARMOR = "ascii_armor"

        const val RESULT_CODE = "result_code"
        const val RESULT_CODE_ERROR = 0
        const val RESULT_CODE_SUCCESS = 1
        const val RESULT_CODE_USER_INTERACTION_REQUIRED = 2
        const val RESULT_INTENT = "intent"
        const val RESULT_KEY_IDS = "key_ids"
        const val RESULT_KEY_ID = "key_id"
        const val RESULT_PRIMARY_USER_ID = "primary_user_id"
        const val RESULT_SIGNATURE = "signature"

        // Signature statuses on a decrypted payload, from the openpgp-api
        // constants. The viewer takes these at face value: OpenKeychain does
        // the verification, this client just reports which of its verdicts
        // came back.
        const val SIGNATURE_STATUS_UNKNOWN = 0
        const val SIGNATURE_STATUS_NO_SIGNATURE = 1
        const val SIGNATURE_STATUS_VALID = 2
        const val SIGNATURE_STATUS_EXPIRED = 3
        const val SIGNATURE_STATUS_KEY_MISSING = 4
        const val SIGNATURE_STATUS_KEY_REVOKED = 5
    }

    /** What a key lookup came back with. */
    sealed interface KeyLookup {
        /** The key ids for the requested user ids. */
        data class Success(val keyIds: LongArray) : KeyLookup

        /** OpenKeychain wants an interaction first (first-use approval, or an
         * ambiguous email); launch the intent, then retry. */
        data class UserInteraction(val pendingIntent: PendingIntent) : KeyLookup

        /** The lookup failed outright. */
        data object Error : KeyLookup
    }

    /**
     * What asking OpenKeychain for a signing key came back with. The API has no
     * way to list the keyring, so the sign key is the one piece of the
     * identity OpenKeychain itself offers: the user picks it in its own
     * picker, and it hands back the key id with the identity it belongs to.
     */
    sealed interface SignKey {
        /** The key the user picked, and the user id it belongs to if reported. */
        data class Picked(val keyId: Long, val userId: String?) : SignKey

        /** OpenKeychain wants to show its key picker first. */
        data class NeedsInteraction(val pendingIntent: PendingIntent) : SignKey

        data object Error : SignKey
    }

    /**
     * What decrypting a payload came back with. The signature verdict is
     * taken at face value from OpenKeychain: [Signature.MISSING_KEY] is the
     * expected answer until counterpart public keys are imported into
     * OpenKeychain, at which point the same bytes verify as [Signature.VALID].
     */
    sealed interface DecryptResult {
        data class Success(
            val target: File,
            val signature: Signature
        ) : DecryptResult

        /** A passphrase prompt, or first-use approval. Launch and retry. */
        data class UserInteraction(val pendingIntent: PendingIntent) : DecryptResult

        data object Error : DecryptResult
    }

    /**
     * What asking OpenKeychain for a public key came back with. The API hands
     * out the whole key, armored on request, so a device can publish the
     * public half of an identity without the owner exporting and pasting it.
     */
    sealed interface PublicKey {
        /** The armored public key, as OpenKeychain wrote it. */
        data class Success(val armored: String) : PublicKey

        /** OpenKeychain wants an interaction first (first-use approval, or a
         * key it does not hold yet and would fetch). Launch, then retry. */
        data class UserInteraction(val pendingIntent: PendingIntent) : PublicKey

        data object Error : PublicKey
    }

    /** The signature verdict OpenKeychain attached to a decrypted payload. */
    enum class Signature(val status: Int) {
        VALID(SIGNATURE_STATUS_VALID),
        NO_SIGNATURE(SIGNATURE_STATUS_NO_SIGNATURE),
        EXPIRED(SIGNATURE_STATUS_EXPIRED),
        MISSING_KEY(SIGNATURE_STATUS_KEY_MISSING),
        KEY_REVOKED(SIGNATURE_STATUS_KEY_REVOKED),
        UNKNOWN(SIGNATURE_STATUS_UNKNOWN);

        companion object {
            fun fromStatus(raw: Int): Signature =
                entries.firstOrNull { it.status == raw } ?: UNKNOWN
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val pipeIdGen = AtomicInteger()
    private var service: IOpenPgpService2? = null
    private var connection: ServiceConnection? = null

    /** Binds OpenKeychain's service and suspends until the binder arrives. */
    private suspend fun connect(): Boolean {
        service?.let { return true }
        val boundService = suspendCancellableCoroutine { continuation ->
            // The package is named rather than left implicit: an implicit
            // service intent only resolves for a package this app can see, and
            // naming it is the documented way to reach OpenKeychain's service.
            val intent = Intent(SERVICE_INTENT_2).setPackage(OPENKEYCHAIN_PACKAGE)
            val newConnection = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                    connection = null
                    continuation.resume(IOpenPgpService2.Stub.asInterface(binder))
                }

                override fun onServiceDisconnected(name: ComponentName) {
                    service = null
                }
            }
            try {
                if (!context.bindService(intent, newConnection, Context.BIND_AUTO_CREATE)) {
                    Log.w(TAG, "OpenKeychain service did not resolve for $SERVICE_INTENT_2")
                    continuation.resume(null)
                    return@suspendCancellableCoroutine
                }
                // Held so close() can unbind: the binding outlives the call.
                connection = newConnection
                continuation.invokeOnCancellation {
                    runCatching { context.unbindService(newConnection) }
                    connection = null
                }
            } catch (e: Exception) {
                Log.w(TAG, "OpenKeychain bind failed: ${e.message}")
                continuation.resume(null)
            }
        }
        service = boundService
        return boundService != null
    }

    /**
     * Runs one OpenPGP call: the input stream is piped to the service, the
     * service's output pipe is pumped into [output], and the call blocks until
     * the result Intent returns. Streams are closed by their pump threads.
     */
    private suspend fun execute(
        data: Intent,
        input: InputStream?,
        output: OutputStream?
    ): Intent = withContext(Dispatchers.IO) {
        val api = service ?: return@withContext errorResult()
        try {
            data.putExtra(EXTRA_API_VERSION, API_VERSION)
            var inputFd: ParcelFileDescriptor? = null
            var outputFd: ParcelFileDescriptor? = null
            var pump: TransferThread? = null
            // The service matches the output pipe by id, so the id used to
            // create it has to be the one handed to execute(). Zero means "no
            // output pipe", which is what the input-only calls pass.
            var pipeId = 0
            try {
                if (input != null) {
                    inputFd = pipeFrom(input)
                }
                if (output != null) {
                    pipeId = pipeIdGen.incrementAndGet()
                    outputFd = api.createOutputPipe(pipeId)
                    pump = pipeTo(output, outputFd, pipeId)
                }
                // Blocks until the service returns; binder calls are already
                // off the main thread via Dispatchers.IO.
                val result = api.execute(data, inputFd, pipeId)
                // Cross-process extras carry lazily-unparceled values —
                // without the app classloader set, parcelable extras (the
                // interaction PendingIntent, OpenPgpError) read as null and
                // Int extras fall back to defaults.
                result.setExtrasClassLoader(context.classLoader)
                pump?.join()
                // The result carries everything the caller needs to diagnose
                // an interaction cycle: on code 2 the PendingIntent to launch;
                // on any failure, OpenKeychain's OpenPgpError (id + message).
                val code = result.getIntExtra(RESULT_CODE, RESULT_CODE_ERROR)
                val err = parcelExtra(
                    result, RESULT_ERROR,
                    org.openintents.openpgp.OpenPgpError::class.java
                )
                Log.i(
                    TAG,
                    "${data.action}: code $code " +
                        (err?.let { "error id=${it.errorId} msg='${it.message}' " } ?: "") +
                        "extras ${result.extras?.keySet()}"
                )
                result
            } finally {
                runCatching { inputFd?.close() }
                runCatching { outputFd?.close() }
            }
        } catch (e: Exception) {
            Log.w(TAG, "OpenPGP call failed: ${e.message}")
            errorResult()
        }
    }

    private fun errorResult(): Intent =
        Intent().putExtra(RESULT_CODE, RESULT_CODE_ERROR)

    /**
     * Typed parcelable read for cross-process result extras. The legacy
     * `getParcelableExtra(key)` returns null on API 33+ results that carry
     * lazily-unparceled values (observed: OpenKeyChain's OpenPgpError), and
     * the typed variant resolves the classloader properly.
     */
    private fun <T : Parcelable> parcelExtra(intent: Intent, key: String, clazz: Class<T>): T? =
        if (android.os.Build.VERSION.SDK_INT >= 33)
            intent.getParcelableExtra(key, clazz)
        else @Suppress("DEPRECATION") intent.getParcelableExtra(key) as? T

    /**
     * Looks up the key ids for [userIds] (emails). No user interaction is
     * offered here; the caller decides what to do with an interaction request.
     */
    override suspend fun lookupKeyIds(userIds: Array<String>, requestData: Intent?): KeyLookup {
        if (!connect()) return KeyLookup.Error
        // After an interaction, the returned intent (with OpenKeychain's call
        // UUIDs) must be the request — see decryptVerify.
        val data = requestData ?: Intent(ACTION_GET_KEY_IDS).apply {
            putExtra(EXTRA_USER_IDS, userIds)
        }
        val result = execute(data, null, null)
        return when (result.getIntExtra(RESULT_CODE, RESULT_CODE_ERROR)) {
            RESULT_CODE_SUCCESS -> {
                val keyIds = result.getLongArrayExtra(RESULT_KEY_IDS)
                if (keyIds != null && keyIds.isNotEmpty()) {
                    KeyLookup.Success(keyIds)
                } else {
                    KeyLookup.Error
                }
            }
            RESULT_CODE_USER_INTERACTION_REQUIRED -> {
                val pendingIntent = parcelExtra(result, RESULT_INTENT, PendingIntent::class.java)
                if (pendingIntent != null) KeyLookup.UserInteraction(pendingIntent) else KeyLookup.Error
            }
            else -> KeyLookup.Error
        }
    }

    /**
     * Fetches the armored public key for [keyId]. This removes the
     * copy-and-paste step from enrollment: the key a counterpart signs with
     * is the key that has to be verified against, and OpenKeychain serves
     * that exact key over the API.
     */
    override suspend fun fetchPublicKeyArmored(keyId: Long): PublicKey {
        if (!connect()) return PublicKey.Error
        val data = Intent(ACTION_GET_KEY).apply {
            putExtra(EXTRA_KEY_ID, keyId)
            putExtra(EXTRA_REQUEST_ASCII_ARMOR, true)
        }
        val sink = ByteArrayOutputStream()
        val result = execute(data, null, sink)
        return when (result.getIntExtra(RESULT_CODE, RESULT_CODE_ERROR)) {
            RESULT_CODE_SUCCESS -> {
                val armored = sink.toString(Charsets.UTF_8.name())
                // An empty or binary answer under a success code is not a key,
                // and enrollment would then publish armor-less bytes as an
                // identity, so the shape is checked before it is handed over.
                if (armored.contains("BEGIN PGP PUBLIC KEY BLOCK")) {
                    PublicKey.Success(armored.trim())
                } else {
                    Log.w(TAG, "GET_KEY returned no armored public key for 0x${keyId.toString(16)}")
                    PublicKey.Error
                }
            }
            RESULT_CODE_USER_INTERACTION_REQUIRED -> {
                val pendingIntent = parcelExtra(result, RESULT_INTENT, PendingIntent::class.java)
                if (pendingIntent != null) PublicKey.UserInteraction(pendingIntent) else PublicKey.Error
            }
            else -> PublicKey.Error
        }
    }

    /**
     * Encrypts [source] to [keyIds] with OpenPGP public-key encryption,
     * writing binary (non-armored) output to [target]. No signing, no
     * passphrase: nothing to enter, so nothing to interact over.
     */
    override suspend fun encryptTo(keyIds: LongArray, source: File, target: File): Boolean {
        if (!connect()) return false
        val data = Intent(ACTION_ENCRYPT).apply {
            putExtra(EXTRA_KEY_IDS, keyIds)
            putExtra(EXTRA_ORIGINAL_FILENAME, source.name)
            putExtra(EXTRA_REQUEST_ASCII_ARMOR, false)
        }
        val result = execute(data, source.inputStream(), target.outputStream())
        val success = result.getIntExtra(RESULT_CODE, RESULT_CODE_ERROR) == RESULT_CODE_SUCCESS
        if (!success) {
            target.delete()
            Log.w(
                TAG,
                "Encryption of ${source.name} failed: code " +
                    result.getIntExtra(RESULT_CODE, RESULT_CODE_ERROR)
            )
        }
        return success
    }

    /**
     * Signs [source] with [signKeyId] and encrypts the signature to
     * [recipientKeyIds] in one pass, writing binary output to [target].
     *
     * [passphrase] is the signing key's, if it has one; omitted for the
     * unprotected keys that unlock on their own. A wrong or missing passphrase
     * comes back as an error rather than a prompt, so the caller decides how
     * to fall back rather than lose the payload.
     */
    suspend fun signAndEncryptTo(
        recipientKeyIds: LongArray,
        signKeyId: Long,
        passphrase: CharArray?,
        source: File,
        target: File
    ): Boolean {
        if (!connect()) return false
        val data = Intent(ACTION_SIGN_AND_ENCRYPT).apply {
            putExtra(EXTRA_KEY_IDS, recipientKeyIds)
            putExtra(EXTRA_SIGN_KEY_ID, signKeyId)
            // The original name rides along as metadata, so the owner gets the
            // clip's name back when they decrypt it.
            putExtra(EXTRA_ORIGINAL_FILENAME, source.name)
            putExtra(EXTRA_REQUEST_ASCII_ARMOR, false)
            if (passphrase != null) putExtra(EXTRA_PASSPHRASE, passphrase)
        }
        val result = execute(data, source.inputStream(), target.outputStream())
        val success = result.getIntExtra(RESULT_CODE, RESULT_CODE_ERROR) == RESULT_CODE_SUCCESS
        if (!success) {
            target.delete()
            Log.w(
                TAG,
                "Sign+encrypt of ${source.name} failed (key 0x${signKeyId.toString(16)}): code " +
                    result.getIntExtra(RESULT_CODE, RESULT_CODE_ERROR)
            )
        }
        return success
    }

    /**
     * Decrypts [source] into [target]. The vault file is encrypted to the
     * enrolled hardware keys, so this is the mirror of [encryptTo]: same
     * pipe arrangement, result carries the signature verdict instead of a
     * sign key. A locked secret or first-use approval comes back as
     * [DecryptResult.UserInteraction] for the activity to launch.
     */
    suspend fun decryptVerify(source: File, target: File, requestData: Intent? = null): DecryptResult {
        if (!connect()) return DecryptResult.Error
        // After an interaction, the returned intent (carrying OpenKeychain's
        // call UUIDs) must be used as the request data — that's how the
        // service finds the cached crypto input; a fresh intent re-prompts.
        val data = requestData ?: Intent(ACTION_DECRYPT_VERIFY)
        val result = execute(data, source.inputStream(), target.outputStream())
        return when (result.getIntExtra(RESULT_CODE, RESULT_CODE_ERROR)) {
            RESULT_CODE_SUCCESS -> DecryptResult.Success(
                target = target,
                signature = Signature.fromStatus(
                    result.getIntExtra(RESULT_SIGNATURE, SIGNATURE_STATUS_UNKNOWN)
                )
            )
            RESULT_CODE_USER_INTERACTION_REQUIRED -> {
                val pendingIntent = parcelExtra(result, RESULT_INTENT, PendingIntent::class.java)
                if (pendingIntent != null) {
                    DecryptResult.UserInteraction(pendingIntent)
                } else {
                    target.delete()
                    DecryptResult.Error
                }
            }
            else -> {
                target.delete()
                Log.w(
                    TAG,
                    "Decrypt of ${source.name} failed: code " +
                        result.getIntExtra(RESULT_CODE, RESULT_CODE_ERROR)
                )
                DecryptResult.Error
            }
        }
    }

    /**
     * The share-this-key Intent OpenKeychain serves, so a device can hand
     * over the public half of its identity without the owner digging through
     * the key manager by hand. The export flow reads the raw user id, looks
     * up the key it belongs to, and passes it on armored as a share. The API
     * surface has no way to read a public key blob out of the keyring
     * directly, so this share (or the owner exporting the key in the
     * OpenKeychain app) is how the public half travels in any case.
     *
     * Returns null when OpenKeychain has nothing registered for the action.
     */
    fun publicKeyShareIntent(userId: String): Intent? {
        val intent = Intent(
            "org.sufficientlysecure.keychain.action.EXPORT_KEY"
        ).setPackage(OPENKEYCHAIN_PACKAGE).apply {
            putExtra("user_id", userId)
            putExtra("ascii_armor", true)
        }
        return if (intent.resolveActivity(context.packageManager) != null) intent else null
    }

    /**
     * Asks OpenKeychain which key to sign with. [data] is the Intent the
     * picker returned, which carries the key the user chose: pass it back in to
     * finish the call. Without it the request starts a new one, which comes
     * back as [SignKey.NeedsInteraction] for the caller to launch.
     */
    suspend fun pickSignKey(data: Intent? = null): SignKey {
        if (!connect()) return SignKey.Error
        val result = execute(
            data ?: Intent(ACTION_GET_SIGN_KEY_ID),
            null,
            null
        )
        return when (result.getIntExtra(RESULT_CODE, RESULT_CODE_ERROR)) {
            RESULT_CODE_SUCCESS -> {
                // OpenKeyChain returns the picked key in the sign_key_id
                // extra (OpenPgpApi.EXTRA_SIGN_KEY_ID) — NOT "key_id".
                val keyId = result.getLongExtra(EXTRA_SIGN_KEY_ID, -1L)
                if (keyId == -1L) {
                    SignKey.Error
                } else {
                    SignKey.Picked(
                        keyId,
                        result.getStringExtra(RESULT_PRIMARY_USER_ID)
                    )
                }
            }
            RESULT_CODE_USER_INTERACTION_REQUIRED -> {
                val pendingIntent = parcelExtra(result, RESULT_INTENT, PendingIntent::class.java)
                if (pendingIntent != null) SignKey.NeedsInteraction(pendingIntent) else SignKey.Error
            }
            else -> SignKey.Error
        }
    }

    /** Releases the binding. The client is unusable afterwards. */
    /**
     * Raw passthrough for spike probing of undocumented API actions
     * (S2: which sign action does OpenKeychain accept, and with what
     * result shape?). Normal app code should use the typed methods.
     */
    suspend fun rawExecute(data: Intent, input: InputStream?, output: OutputStream?): Intent =
        execute(data, input, output)

    /**
     * Detached PGP signature over [data], armored — OpenKeyChain returns it
     * in the `detached_signature` extra (the output pipe stays empty for
     * this action). Structured result so callers can surface OpenKeyChain's
     * passphrase/plug-in prompt through the UI interaction loop before any
     * commit depends on the key being unlocked.
     */
    sealed interface SignDetached {
        data class Ok(val armored: String) : SignDetached
        data class UserInteraction(val pendingIntent: PendingIntent) : SignDetached
        data class Error(val message: String) : SignDetached
    }

    override suspend fun trySignDetached(
        data: ByteArray,
        keyId: Long,
        requestData: Intent?
    ): SignDetached {
        if (!connect()) return SignDetached.Error("OpenKeyChain service unavailable")
        val intent = requestData ?: Intent(ACTION_DETACHED_SIGN).apply {
            putExtra(EXTRA_SIGN_KEY_ID, keyId)
            putExtra(EXTRA_REQUEST_ASCII_ARMOR, true)
        }
        val sink = ByteArrayOutputStream()
        val result = execute(intent, data.inputStream(), sink)
        return when (result.getIntExtra(RESULT_CODE, RESULT_CODE_ERROR)) {
            RESULT_CODE_SUCCESS -> {
                val raw = result.extras?.get("detached_signature") as? ByteArray
                if (raw != null && raw.isNotEmpty()) {
                    SignDetached.Ok(String(raw, Charsets.UTF_8))
                } else {
                    SignDetached.Error("no detached signature returned")
                }
            }
            RESULT_CODE_USER_INTERACTION_REQUIRED -> {
                val pi = parcelExtra(result, RESULT_INTENT, PendingIntent::class.java)
                if (pi != null) SignDetached.UserInteraction(pi)
                else SignDetached.Error("interaction requested but no intent returned")
            }
            else -> {
                val err = parcelExtra(
                    result, RESULT_ERROR,
                    org.openintents.openpgp.OpenPgpError::class.java
                )
                SignDetached.Error(err?.message?.takeIf { it.isNotBlank() }
                    ?: "error id ${err?.errorId ?: -1}")
            }
        }
    }

    /** Releases the binding. The client is unusable afterwards. */
    fun close() {
        scope.cancel()
        connection?.let { runCatching { context.unbindService(it) } }
        connection = null
        service = null
    }

    /** Pumps [input] into a pipe write side, returning the read side for the service. */
    private fun pipeFrom(input: InputStream): ParcelFileDescriptor {
        val pipe = ParcelFileDescriptor.createPipe()
        TransferThread(input, ParcelFileDescriptor.AutoCloseOutputStream(pipe[1]), -1).start()
        return pipe[0]
    }

    /** Pumps the service's output pipe for [pipeId] into [output]. */
    private fun pipeTo(output: OutputStream, serviceFd: ParcelFileDescriptor, pipeId: Int): TransferThread =
        TransferThread(ParcelFileDescriptor.AutoCloseInputStream(serviceFd), output, pipeId)
            .also { it.start() }

    /**
     * Carries the output pipe id it is pumping for; the service identifies its
     * output pipe by that id, not by the descriptor.
     */
    private class TransferThread(
        private val input: InputStream,
        private val output: OutputStream,
        val id: Int
    ) : Thread("OpenPGP transfer") {
        init {
            isDaemon = true
        }

        override fun run() {
            val buffer = ByteArray(64 * 1024)
            try {
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    output.write(buffer, 0, read)
                }
            } catch (_: IOException) {
                // A closed pipe mid-transfer is how a failing call ends.
            } finally {
                // During decrypt this buffer carried plaintext chunks —
                // zero it before the thread dies.
                buffer.fill(0)
                runCatching { input.close() }
                runCatching { output.close() }
            }
        }
    }
}
