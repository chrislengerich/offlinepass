package com.offlinepass.app.crypto

import android.content.Context
import android.hardware.usb.UsbManager
import android.util.Log
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import com.yubico.yubikit.core.keys.PublicKeyValues
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.KeyRef
import com.yubico.yubikit.openpgp.OpenPgpSession

/**
 * The YubiKit backend for the envelope DECRYPT: the card recovers the
 * session key (PSO:DEC on the DECRYPTION slot) and BouncyCastle's bcpg
 * does all the OpenPGP framing — no OpenKeyChain in the path.
 *
 * One USB connection carries the whole decrypt: the DEC slot's
 * fingerprint read (which PKESK to feed the card), the user-PIN verify,
 * the modulus read (the ciphertext padding length), and the PSO:DEC
 * itself. The touch policy applies on the hardware side (the DEC slot's
 * UIF): [touch] wraps the card op in the router's touch prompt.
 *
 * Why direct: OpenKeyChain's remote API decrypt works but costs an app
 * switch, an API-allow dance, and — on this ROM — an app kill while OKK
 * foregrounds. The direct card op keeps the load in-process.
 */
object YubiKitCardDecrypt {

    private const val TAG = "YubiKitCardDecrypt"

    /**
     * Decrypts an OpenPGP message (the vault envelope) with the card's
     * DECRYPTION slot, returning the original plaintext.
     *
     * [pin] = the OpenPGP user PIN (verified on the applet before the
     * decrypt). [touch] wraps the card operation (PSO:DEC) in the touch
     * prompt — a suspend hook so the prompt can drive the UI.
     */
    suspend fun decryptEnvelopeBytes(
        context: Context,
        msgBytes: ByteArray,
        pin: CharArray,
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
        Log.i(TAG, "yubikit: opening SmartCardConnection for the decrypt")
        val connection = ykDevice.openConnection(SmartCardConnection::class.java)
        try {
            val session = OpenPgpSession(connection as SmartCardConnection)
            try {
                Log.i(TAG, "yubikit: applet=${session.getVersion()}")
                // The user PIN gates PSO:DEC on the OpenPGP applet. A wrong
                // PIN burns one of the card's 3 attempts — surface the
                // remaining count, never silently walk toward a lockout.
                try {
                    session.verifyUserPin(pin, false)
                } catch (e: com.yubico.yubikit.core.application.InvalidPinException) {
                    val left = runCatching { session.pinStatus.attemptsUser }.getOrDefault(-1)
                    throw java.io.IOException(
                        if (left >= 0) "wrong OpenPGP PIN — $left attempt(s) left before the key locks"
                        else "wrong OpenPGP PIN", e)
                }
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
                // The ciphertext must be the modulus length on the wire.
                val modulusLen = when (val pub = session.getPublicKey(KeyRef.DEC)) {
                    is PublicKeyValues.Rsa -> (pub.modulus.bitLength() + 7) / 8
                    else -> throw java.io.IOException(
                        "the DECRYPTION slot is not RSA — only the RSA decrypt is supported")
                }
                Log.i(TAG, "yubikit: DEC key id 0x%016X, modulus $modulusLen bytes".format(decKeyId))
                return OpenPgpCardCrypto.decrypt(msgBytes, longArrayOf(decKeyId)) { mpiValue ->
                    val padded = ByteArray(modulusLen) { 0 }
                    mpiValue.copyInto(padded, modulusLen - mpiValue.size)
                    touch { session.decrypt(padded) }
                }
            } finally {
                session.close()
            }
        } finally {
            runCatching { connection.close() }
        }
    }
}
