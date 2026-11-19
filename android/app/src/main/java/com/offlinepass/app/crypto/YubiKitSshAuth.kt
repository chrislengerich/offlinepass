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
 * The card's SIGNATURE slot is used (PSO:CDS) — the S subkey already
 * enrolled on GitHub. The card does the PKCS#1 v1.5 padding on-device:
 * the caller supplies the BARE DigestInfo (`SshRsaPkcs1.digestInfo`) and
 * receives the raw RSA result over the padded block — exactly what an
 * ssh-rsa signature carries.
 *
 * Measured on-device (YubiKey 5, RSA-4096): PSO:CDS with the small
 * DigestInfo command is the configuration that passes the full chain;
 * long (512-byte) command payloads fail with 0x6581 on this transport —
 * both the padded PSO:CDS block and the AUT slot's INTERNAL AUTHENTICATE
 * challenge (which has no on-card padding and thus always requires 512
 * bytes for a 4096-bit key). The AUT slot stays a documented dead end
 * until a transport-level fix exists.
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

    /** The cardholder name from DO 0x0065 (unauthenticated): a 39-byte
     *  fixed field, gpg's "SURNAME<<Given" convention → "Given Surname".
     *  Null when the field is empty. */
    fun parseHolderName(raw: ByteArray): String? {
        val name = raw.take(39)
            .map { b -> if (b == '<'.code.toByte()) ' ' else b.toChar() }
            .joinToString("").trim()
        return name.ifEmpty { null }
    }

    data class CardIdentity(
        val keyId: Long,
        val fingerprint: ByteArray,
        val holderName: String?
    )

    /** The SIGNATURE slot's identity — an unauthenticated GET DATA: no
     *  PIN, no touch. The key id = the fingerprint's last 8 bytes (the v4
     *  fingerprint's low half); the holder name = the card's own. */
    fun signingKeyIdentity(context: Context): CardIdentity {
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
                val fp = session.applicationRelatedData.discretionary
                    .getFingerprint(com.yubico.yubikit.openpgp.KeyRef.SIG)
                if (fp == null || fp.size < 20) {
                    throw java.io.IOException("the card reports no SIGNATURE fingerprint " +
                        "(an empty slot?)")
                }
                val keyId = (12 until 20).fold(0L) { acc, k ->
                    (acc shl 8) or (fp[k].toLong() and 0xFF)
                }
                val holder = runCatching {
                    parseHolderName(session.getData(0x0065))
                }.getOrNull()
                return CardIdentity(keyId, fp, holder)
            } finally {
                session.close()
            }
        } finally {
            runCatching { connection.close() }
        }
    }

    /**
     * Verifies the OpenPGP user PIN on the applet, then signs [payload]
     * (the pre-built PKCS#1 v1.5 block) with the card's SIGNATURE slot.
     * The YubiKey's slot touch policy applies on the hardware side.
     */
    /** The slot's LIVE public key as the ssh-keygen SHA256 fingerprint
     *  (no PIN, no touch — the unauthenticated GET DATA path): the
     *  "which key" answer for the auth logs and the self-test verdict —
     *  the same format GitHub's security log shows, so a live-vs-enrolled
     *  mismatch is detectable in one comparison. RSA only (the AUT path
     *  is RSA-mandatory); null when the read fails or the slot is
     *  non-RSA. */
    fun slotKeyFingerprint(context: Context, useAut: Boolean): String? {
        val device = findDevice(context) ?: return null
        val usbManager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
            ?: return null
        if (!usbManager.hasPermission(device)) return null
        val ykDevice = UsbYubiKeyDevice(usbManager, device)
        val connection = ykDevice.openConnection(SmartCardConnection::class.java)
        try {
            val session = OpenPgpSession(connection as SmartCardConnection)
            try {
                val ref = if (useAut) com.yubico.yubikit.openpgp.KeyRef.AUT
                else com.yubico.yubikit.openpgp.KeyRef.SIG
                return when (val pub = session.getPublicKey(ref)) {
                    is com.yubico.yubikit.core.keys.PublicKeyValues.Rsa ->
                        com.offlinepass.app.crypto.PgpSshBridge
                            .rsaFingerprint(pub.modulus, pub.publicExponent)
                    else -> null
                }
            } finally {
                session.close()
            }
        } finally {
            runCatching { connection.close() }
        }
    }

    /**
     * Verifies the OpenPGP user PIN on the applet, then signs or
     * authenticates. The slot choice:
     *
     * - **SIG (default)** — PSO:CDS on the SIGNATURE slot; the card pads
     *   the bare DigestInfo itself (the payload = the DigestInfo).
     * - **AUT (useAut)** — INTERNAL AUTHENTICATE on the AUTHENTICATION
     *   slot: NO on-card padding, so the caller's payload = the FULL
     *   PKCS#1 v1.5 type-1 block, padded here to the AUT key's modulus
     *   length (the RSA-4096 = a 512-byte command — this path is the
     *   long-command transport's test; the YubiKit 3.3.0 core added the
     *   ExtendedApduProcessor). The output = the raw RSA result — the
     *   same operation the RSA sign is — so it verifies as an
     *   ssh-rsa/rsa-sha2 signature unchanged (proven by AutKeyPathTest).
     *   The AUT key = the DEDICATED authentication key: the SIG key
     *   stays pure signing.
     *
     * The PIN flavor (extended=false = P2:0x81) = the hypothesis for
     * INTERNAL AUTHENTICATE; the self-test tries both flavors on-device
     * before this path goes default.
     */
    fun sign(
        context: Context,
        pin: CharArray,
        payload: ByteArray,
        useAut: Boolean = false,
        expectedFingerprint: String? = null
    ): ByteArray {
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
                // Card facts for the log channel: the applet version, the
                // touch requirement per slot, and the command size — the
                // 0x6581s so far all involved 512-byte 4096-bit payloads.
                android.util.Log.i("YubiKeySsh",
                    "yubikit: applet=${session.getVersion()} " +
                        "uifSIG=${session.getUif(com.yubico.yubikit.openpgp.KeyRef.SIG)} " +
                        "uifAUT=${session.getUif(com.yubico.yubikit.openpgp.KeyRef.AUT)} " +
                        "payload=${payload.size}B")
                // THE WHICH-KEY READ + THE PRE-SIGN GATE: the live public
                // key of the slot about to answer — read UNAUTHENTICATED
                // (no PIN, no touch) BEFORE the PIN verify. Logged always;
                // when the caller passes an expected fingerprint (the
                // enrolled line's), a mismatch REFUSES to sign by name —
                // the sig GitHub would reject is never produced, and the
                // PIN attempt is never spent.
                val liveFp: String = runCatching {
                    when (val pub = session.getPublicKey(
                        if (useAut) com.yubico.yubikit.openpgp.KeyRef.AUT
                        else com.yubico.yubikit.openpgp.KeyRef.SIG)) {
                        is com.yubico.yubikit.core.keys.PublicKeyValues.Rsa ->
                            com.offlinepass.app.crypto.PgpSshBridge
                                .rsaFingerprint(pub.modulus, pub.publicExponent)
                        else -> "non-RSA (${pub.javaClass.simpleName})"
                    }
                }.getOrElse { "unreadable" }
                android.util.Log.i("YubiKeySsh",
                    "yubikit: auth key " + (if (useAut) "AUT" else "SIG") + " fp=$liveFp")
                if (expectedFingerprint != null && liveFp != expectedFingerprint) {
                    throw java.io.IOException(
                        "refusing to sign: the card's " +
                            (if (useAut) "AUT" else "SIG") +
                            " key is $liveFp, expected $expectedFingerprint — " +
                            "wrong card or stale enrollment")
                }
                // extended=false = verify FOR SIGNATURE (the Javadoc:
                // "false to verify for signature use, true for other
                // uses"). True → P2=0x82 and PSO:CDS fails 0x6982.
                // A WRONG PIN surfaces as a readable message (attempts
                // remaining) instead of a raw "APDU error: 0x63CX".
                try {
                    session.verifyUserPin(pin, false)
                } catch (e: com.yubico.yubikit.core.application.InvalidPinException) {
                    throw java.io.IOException(
                        "Wrong PIN — ${e.attemptsRemaining} attempt(s) remaining " +
                            "(the 3rd failure blocks the PIN)", e)
                } catch (e: com.yubico.yubikit.core.smartcard.ApduException) {
                    val sw = e.sw.toInt()
                    if (sw and 0xFFF0 == 0x63C0) {
                        // OpenPGP spec: a wrong PW1 answers 63 CX, X = the
                        // attempts left.
                        throw java.io.IOException(
                            "Wrong PIN — ${sw and 0x0F} attempt(s) remaining " +
                                "(the 3rd failure blocks the PIN)", e)
                    }
                    throw e
                }
                android.util.Log.i("YubiKeySsh",
                    "yubikit: PIN verified — " +
                        (if (useAut) "INTERNAL AUTHENTICATE on the AUTH slot"
                        else "PSO:CDS on the SIGNATURE slot") +
                        " (touch the key if its LED blinks)")
                val sig = if (useAut) {
                    // The raw-RSA path: the challenge = the FULL PKCS#1
                    // block padded to the AUT modulus (no on-card padding).
                    val autPub = session.getPublicKey(com.yubico.yubikit.openpgp.KeyRef.AUT)
                    val modulusLen = when (val pub = autPub) {
                        is com.yubico.yubikit.core.keys.PublicKeyValues.Rsa ->
                            (pub.modulus.bitLength() + 7) / 8
                        else -> throw java.io.IOException(
                            "the AUT slot is not RSA — the AUT path needs an RSA authentication key")
                    }
                    require(payload.size <= modulusLen) {
                        "the payload (${payload.size}B) exceeds the AUT modulus ($modulusLen B)"
                    }
                    val block = ByteArray(modulusLen) { 0 }
                    payload.copyInto(block, modulusLen - payload.size)
                    android.util.Log.i("YubiKeySsh",
                        "yubikit: challenge padded to $modulusLen B")
                    session.authenticate(block)
                } else {
                    session.sign(payload)
                }
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
