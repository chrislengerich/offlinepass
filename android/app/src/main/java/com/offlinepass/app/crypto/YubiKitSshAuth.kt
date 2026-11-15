package com.offlinepass.app.crypto

import android.content.Context
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.OpenPgpSession

/**
 * The YubiKit backend for SSH signing: talks to the OpenPGP applet
 * DIRECTLY over USB — no OpenKeyChain in the path.
 *
 * Why this exists: OpenKeyChain's remote API decrypts with card-resident
 * keys but its sign action rejects them (UNSUPPORTED_ACTION, measured).
 * YubiKit performs the card operation directly: the user PIN is verified
 * on the OpenPGP applet, then the card computes the signature on the
 * SIGNATURE slot — which is the S subkey already enrolled on GitHub (the
 * same line the OKK/software path used), so no re-enrollment is needed.
 *
 * The caller supplies the PKCS#1 v1.5 block (`SshRsaPkcs1`) and receives
 * the RAW signature bytes (the card's RSA over the DigestInfo — exactly
 * what an ssh-rsa signature carries).
 */
object YubiKitSshAuth {

    private const val YUBICO_VENDOR_ID = 0x1050

    /** The connected YubiKey (the Yubico vendor id), or null. */
    fun findDevice(context: Context): UsbDevice? {
        val usbManager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
            ?: return null
        return usbManager.deviceList.values.firstOrNull { it.vendorId == YUBICO_VENDOR_ID }
    }

    /** A YubiKey is attached AND the USB permission for it is granted. */
    fun deviceReady(context: Context): Boolean {
        val device = findDevice(context) ?: return false
        val usbManager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
            ?: return false
        return usbManager.hasPermission(device)
    }

    /**
     * Verifies the OpenPGP user PIN on the applet, then signs [payload]
     * (the pre-built PKCS#1 v1.5 block) with the card's SIGNATURE slot.
     * The YubiKey's slot touch policy applies on the hardware side.
     */
    fun sign(context: Context, pin: CharArray, payload: ByteArray): ByteArray {
        val device = findDevice(context)
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
                session.verifyUserPin(pin, true)
                return session.sign(payload)
            } finally {
                session.close()
            }
        } finally {
            runCatching { connection.close() }
        }
    }
}
