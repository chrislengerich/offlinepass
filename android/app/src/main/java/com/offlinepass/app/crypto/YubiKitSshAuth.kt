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
 * The card's AUT slot is used (INTERNAL AUTHENTICATE) — the SAME key the
 * desktop gpg-agent serves for SSH and the one enrolled on GitHub. Unlike
 * the SIG slot's PSO:CDS, INTERNAL AUTHENTICATE does RAW RSA with NO
 * on-card padding, so the caller supplies the FULL PKCS#1 v1.5 block
 * (`SshRsaPkcs1.pkcs1SignBlock`) and receives the raw RSA result —
 * exactly what an ssh-rsa signature carries.
 */
object YubiKitSshAuth {

    init {
        // The connection handlers (SmartCard/OTP/FIDO) are registered into
        // ConnectionManager's static registry by UsbYubiKeyManager's class
        // initializer. Constructing UsbYubiKeyDevice DIRECTLY (as this
        // object does, without the manager's attach listener) skips that
        // class entirely — and openConnection then fails with
        // "Unsupported connection type". Touch the manager class once so
        // the registry is populated.
        runCatching {
            Class.forName(
                "com.yubico.yubikit.android.transport.usb.UsbYubiKeyManager")
        }
    }

    private const val YUBICO_VENDOR_ID = 0x1050

    /** The connected YubiKey (the Yubico vendor id), or null. */
    fun findDevice(context: Context): UsbDevice? {
        val usbManager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
            ?: return null
        return usbManager.deviceList.values.firstOrNull { it.vendorId == YUBICO_VENDOR_ID }
    }

    /** The attached-device diagnostic string: the device name/vid/pid and
     *  the USB permission state — or "(no YubiKey enumerated)". */
    fun deviceInfo(context: Context): String {
        val usbManager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
            ?: return "no USB service"
        val devices = usbManager.deviceList
        val yubi = devices.values.firstOrNull { it.vendorId == YUBICO_VENDOR_ID }
            ?: return "no YubiKey enumerated (${devices.size} USB devices)"
        return "${yubi.deviceName} vid=${"%04x".format(yubi.vendorId)} " +
            "pid=${"%04x".format(yubi.productId)} " +
            "permission=${usbManager.hasPermission(yubi)}"
    }

    /** A YubiKey is attached AND the USB permission for it is granted. */
    fun deviceReady(context: Context): Boolean {
        val device = findDevice(context) ?: return false
        val usbManager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
            ?: return false
        return usbManager.hasPermission(device)
    }

    private const val PERMISSION_ACTION = "com.offlinepass.app.USB_PERMISSION"

    /**
     * Asks the user to grant USB access to the YubiKey (the system's
     * "allow access to USB device" dialog) and suspends until the grant
     * or denial. Returns true when granted.
     */
    suspend fun requestPermission(context: Context): Boolean {
        val device = findDevice(context) ?: return false
        val usbManager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
            ?: return false
        if (usbManager.hasPermission(device)) return true
        return kotlinx.coroutines.suspendCancellableCoroutine { cont ->
            val receiver = object : android.content.BroadcastReceiver() {
                override fun onReceive(ctx: Context, intent: android.content.Intent) {
                    context.unregisterReceiver(this)
                    val granted = intent.getBooleanExtra(
                        android.hardware.usb.UsbManager.EXTRA_PERMISSION_GRANTED, false)
                    if (cont.isActive) cont.resume(granted, onCancellation = null)
                }
            }
            context.registerReceiver(receiver, android.content.IntentFilter(PERMISSION_ACTION),
                if (android.os.Build.VERSION.SDK_INT >= 33)
                    android.content.Context.RECEIVER_EXPORTED else 0)
            val pi = android.app.PendingIntent.getBroadcast(
                context, 0,
                android.content.Intent(PERMISSION_ACTION).setPackage(context.packageName),
                if (android.os.Build.VERSION.SDK_INT >= 31)
                    android.app.PendingIntent.FLAG_MUTABLE else 0)
            usbManager.requestPermission(device, pi)
        }
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
        android.util.Log.i("YubiKeySsh", "yubikit: opening SmartCardConnection to ${device.deviceName}")
        val connection = ykDevice.openConnection(SmartCardConnection::class.java)
        android.util.Log.i("YubiKeySsh", "yubikit: connection open — verifying the user PIN")
        try {
            val session = OpenPgpSession(connection as SmartCardConnection)
            try {
                // INTERNAL AUTHENTICATE (the AUT slot) requires the PW1
                // verified "for other" — extended=TRUE here (P2=0x82; for
                // the SIG slot this exact flag was the 0x6982 bug).
                session.verifyUserPin(pin, true)
                android.util.Log.i("YubiKeySsh",
                    "yubikit: PIN verified — INTERNAL AUTHENTICATE on the " +
                        "AUTH slot (touch the key if its LED blinks)")
                val sig = session.authenticate(payload)
                android.util.Log.i("YubiKeySsh", "yubikit: card signed (${sig.size} bytes)")
                return sig
            } finally {
                session.close()
            }
        } finally {
            runCatching { connection.close() }
            android.util.Log.i("YubiKeySsh", "yubikit: connection closed")
        }
    }
}
