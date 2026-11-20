package com.offlinepass.app.crypto

import android.content.Context
import android.hardware.usb.UsbManager
import android.util.Log
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import com.yubico.yubikit.core.keys.PublicKeyValues
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.KeyRef
import com.yubico.yubikit.openpgp.OpenPgpSession

/** The card REJECTED the PIN — the caller must invalidate its cache: a
 *  proven-wrong cached PIN must never be retried (each retry burns one
 *  of the card's 3 attempts). */
class OpenPgpPinRejected(message: String, cause: Throwable? = null) :
    java.io.IOException(message, cause)

/**
 * The YubiKit backend for the envelope DECRYPT: the card recovers the
 * session key (PSO:DEC on the DECRYPTION slot) and BouncyCastle's bcpg
 * does all the OpenPGP framing — no OpenKeyChain in the path.
 *
 * One USB connection carries the whole decrypt: the DEC slot's
 * fingerprint read (which PKESK to feed the card), the modulus read (the
 * ciphertext padding length), the user-PIN verify, and the PSO:DEC
 * itself. The touch policy applies on the hardware side (the DEC slot's
 * UIF): [touch] wraps the card op in the router's touch prompt.
 *
 * THE OP ORDER IS LOAD-BEARING: the public-key reads run BEFORE the PIN
 * verify, and the verify itself uses the "extended" flavor (YubiKit's
 * `verifyUserPin(pin, true)`, P2=0x82): with the plain signature-only
 * flavor (P2=0x81) the verify returns 9000 but PSO:DEC answers APDU
 * 0x6982 "security status not satisfied" — measured on-device on a card
 * whose DEC slot is RSA-4096 (a 512-byte command payload). Verifying
 * LAST makes the PSO:DEC the very next command after the 9000.
 *
 * Why direct: OpenKeyChain's remote API decrypt works but costs an app
 * switch, an API-allow dance, and — on this ROM — an app kill while OKK
 * foregrounds. The direct card op keeps the load in-process.
 */
object YubiKitCardDecrypt {

    private const val TAG = "YubiKitCardDecrypt"

    /** The DECRYPTION slot's key id — an unauthenticated read (no PIN, no
     *  touch). The id = the v4 fingerprint's low half — the same id the
     *  vault's PKESKs name. Used to auto-add the card as a new vault's
     *  first recipient. */
    fun decKeyId(context: Context): Long {
        val device = YubiKitSshAuth.findDevice(context)
            ?: throw java.io.IOException("no YubiKey connected")
        val usbManager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
            ?: throw java.io.IOException("USB service unavailable")
        if (!usbManager.hasPermission(device)) {
            throw java.io.IOException("USB permission not granted for the YubiKey")
        }
        val ykDevice = UsbYubiKeyDevice(usbManager, device)
        val connection = ykDevice.openConnection(SmartCardConnection::class.java)
        try {
            val session = OpenPgpSession(connection as SmartCardConnection)
            try {
                val decFp = session.applicationRelatedData.discretionary
                    .getFingerprint(KeyRef.DEC)
                if (decFp == null || decFp.size < 20) {
                    throw java.io.IOException("the card reports no DECRYPTION fingerprint (an empty slot?)")
                }
                return (12 until 20).fold(0L) { acc, k ->
                    (acc shl 8) or (decFp[k].toLong() and 0xFF)
                }
            } finally {
                session.close()
            }
        } finally {
            runCatching { connection.close() }
        }
    }

    /**
     * Decrypts an OpenPGP message (the vault envelope) with the card's
     * DECRYPTION slot, returning the original plaintext.
     *
     * [pin] = the OpenPGP user PIN (verified on the applet just before
     * the decrypt). [log] = the diagnostics channel (this ROM's logd is
     * unreliable; the breadcrumbs must land in the pullable log).
     * [touch] wraps the card operation (PSO:DEC) in the touch prompt —
     * a suspend hook so the prompt can drive the UI.
     */
    suspend fun decryptEnvelopeBytes(
        context: Context,
        msgBytes: ByteArray,
        pin: CharArray,
        log: (String) -> Unit,
        touch: suspend (() -> ByteArray) -> ByteArray,
    ): ByteArray {
        val device = YubiKitSshAuth.findDevice(context)
            ?: throw java.io.IOException("no YubiKey connected")
        val usbManager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
            ?: throw java.io.IOException("USB service unavailable")
        if (!usbManager.hasPermission(device)) {
            throw java.io.IOException("USB permission not granted for the YubiKey")
        }
        val ykDevice = UsbYubiKeyDevice(usbManager, device)
        log("yubikit-decrypt: opening SmartCardConnection")
        Log.i(TAG, "yubikit: opening SmartCardConnection for the decrypt")
        val connection = ykDevice.openConnection(SmartCardConnection::class.java)
        try {
            val session = OpenPgpSession(connection as SmartCardConnection)
            try {
                log("yubikit-decrypt: applet=${session.getVersion()}")
                Log.i(TAG, "yubikit: applet=${session.getVersion()}")
                // The DEC slot's fingerprint → the PKESK dispatch id (an
                // unauthenticated read; the key id = the fp's low half).
                val decFp = session.applicationRelatedData.discretionary
                    .getFingerprint(KeyRef.DEC)
                if (decFp == null || decFp.size < 20) {
                    throw java.io.IOException("the card reports no DECRYPTION fingerprint (an empty slot?)")
                }
                val decKeyId = (12 until 20).fold(0L) { acc, k ->
                    (acc shl 8) or (decFp[k].toLong() and 0xFF)
                }
                // The ciphertext's wire length: RSA = the modulus length
                // (the zero-padded MPI); EC = the ephemeral point (65 bytes
                // for P-256, NO padding — the card performs the RFC 6637
                // KDF + the AES-key-unwrap and returns the plain session
                // data).
                val (commandLen, padded) = when (val pub = session.getPublicKey(KeyRef.DEC)) {
                    is PublicKeyValues.Rsa -> {
                        val modulusLen = (pub.modulus.bitLength() + 7) / 8
                        Pair(modulusLen, true)
                    }
                    is PublicKeyValues.Ec -> {
                        // The point length = the encoded SEC1 point's size
                        // (65 bytes for P-256).
                        Pair(pub.encodedPoint.size, false)
                    }
                    else -> throw java.io.IOException(
                        "the DECRYPTION slot key type is unsupported (${pub.javaClass.simpleName})")
                }
                log("yubikit-decrypt: DEC key id 0x%016X, command $commandLen bytes (${if (padded) "RSA-padded" else "EC point"})".format(decKeyId))
                Log.i(TAG, "yubikit: DEC key id 0x%016X, $commandLen-byte command (${if (padded) "RSA" else "ECDH"})".format(decKeyId))
                // THE VAULT→CARD PRE-CHECK: the ciphertext's PKESK recipients
                // vs the live DEC key — a wrong card fails BY NAME here,
                // before the PIN (the decrypt could never open anyway; the
                // PIN attempt would be pure loss).
                runCatching { OpenPgpCardCrypto.pkeskKeyIds(msgBytes) }.onSuccess { ids ->
                    if (ids.isNotEmpty() && decKeyId !in ids) {
                        val listed = ids.joinToString(", ") { "0x%016X".format(it) }
                        val msg = ("this vault is encrypted to key(s) $listed; " +
                            "the attached card's DEC key is 0x%016X — wrong card?"
                            ).format(decKeyId)
                        log("yubikit-decrypt: $msg")
                        Log.w(TAG, "yubikit: $msg")
                        throw java.io.IOException(msg)
                    }
                }
                // THE VERIFY = THE "EXTENDED" FLAVOR: with extended=false
                // YubiKit verifies PW1 for SIGNATURE USE ONLY (P2=0x81) —
                // the PSO:DEC then fails with 0x6982 despite the verify's
                // own 9000. extended=true = P2=0x82 = the decrypt-capable
                // verify (the sign is then NOT allowed in this session —
                // the sign runs in its own session, fine).
                try {
                    session.verifyUserPin(pin, true)
                } catch (e: com.yubico.yubikit.core.application.InvalidPinException) {
                    val left = runCatching { session.pinStatus.attemptsUser }.getOrDefault(-1)
                    val msg = if (left >= 0) "wrong OpenPGP PIN — $left attempt(s) left before the key locks"
                              else "wrong OpenPGP PIN"
                    log("yubikit-decrypt: $msg")
                    Log.w(TAG, "yubikit: $msg")
                    throw OpenPgpPinRejected(msg, e)
                }
                log("yubikit-decrypt: PIN verified (extended) — PSO:DEC next")
                Log.i(TAG, "yubikit: PIN verified (extended) — PSO:DEC next ($commandLen-byte command)")
                val plain = OpenPgpCardCrypto.decrypt(msgBytes, longArrayOf(decKeyId)) { mpiValue ->
                    if (padded) {
                        // RSA: the card wants the zero-padded MPI; the response
                        // = the PKCS#1 type-2 block (or the unpadded M on the
                        // newer applets — the factory handles both shapes).
                        val paddedBlock = ByteArray(commandLen) { 0 }
                        mpiValue.copyInto(paddedBlock, commandLen - mpiValue.size)
                        touch { session.decrypt(paddedBlock) }
                    } else {
                        // ECDH: the card wants the bare ephemeral POINT (the
                        // MPI value, the 0x04-prefixed SEC1 encoding) and
                        // returns the plain session data (the card did the
                        // RFC 6637 KDF + the AES-key-unwrap internally).
                        touch { session.decrypt(mpiValue) }
                    }
                }
                log("yubikit-decrypt: plaintext recovered (${plain.size}B)")
                Log.i(TAG, "yubikit: plaintext recovered (${plain.size}B)")
                return plain
            } finally {
                session.close()
            }
        } finally {
            runCatching { connection.close() }
        }
    }
}
