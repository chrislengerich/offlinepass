package com.offlinepass.app.crypto

import android.app.Activity

/**
 * The screenlock gate: the device-credential/biometric prompt WITHOUT a
 * CryptoObject — a successful prompt opens the keystore keys' 60s validity
 * window (the timestamp is global across the app's time-based keys: the
 * reveal prompt and the commit-signing prompt share one window).
 */
object ScreenlockGate {

    /** THE TEST SEAM: the full-flow Robolectric tests stub the gate (the
     *  real BiometricPrompt is untestable in the JVM) — null = the real
     *  prompt. */
    internal var testGate: (suspend (Activity, String, String) -> Boolean)? = null

    suspend fun promptGate(
        activity: Activity,
        title: String,
        subtitle: String,
        strongOrCredential: Boolean = false
    ): Boolean {
        testGate?.let { return it(activity, title, subtitle) }
        return kotlinx.coroutines.suspendCancellableCoroutine { cont ->
            val cancel = android.os.CancellationSignal()
            val builder = android.hardware.biometrics.BiometricPrompt.Builder(activity)
                .setTitle(title)
                .setSubtitle(subtitle)
            if (android.os.Build.VERSION.SDK_INT >= 30) {
                // THE MODERN AUTHENTICATORS (the API 30+): the credential
                // renders INSIDE the prompt dialog — NO activity switch.
                // The legacy setDeviceCredentialAllowed(true) launched the
                // system's credential ACTIVITY on the PIN fallback, whose
                // result bubbled to the framework's auth tracking as an
                // EMPTY intent and consumed the dataset's authentication
                // before the flow's own result (the measured post-generate
                // fill loss: the re-offered chip instead of the fill).
                builder.setAllowedAuthenticators(
                    if (strongOrCredential)
                        android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL
                    else
                        android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_WEAK or
                            android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            } else {
                builder.setDeviceCredentialAllowed(true)
            }
            val prompt = builder.build()
            cont.invokeOnCancellation { cancel.cancel() }
            prompt.authenticate(
                cancel,
                androidx.core.content.ContextCompat.getMainExecutor(activity),
                object : android.hardware.biometrics.BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(
                        result: android.hardware.biometrics.BiometricPrompt.AuthenticationResult
                    ) { cont.resume(true, onCancellation = null) }
                    override fun onAuthenticationError(code: Int, errString: CharSequence) {
                        android.util.Log.w("ScreenlockGate", "gate: $code $errString")
                        cont.resume(false, onCancellation = null)
                    }
                }
            )
        }
    }
}
