package com.offlinepass.app.crypto

import android.app.Activity

/**
 * The screenlock gate: the device-credential/biometric prompt WITHOUT a
 * CryptoObject — a successful prompt opens the keystore keys' 60s validity
 * window (the timestamp is global across the app's time-based keys: the
 * reveal prompt and the commit-signing prompt share one window).
 */
object ScreenlockGate {
    suspend fun promptGate(
        activity: Activity,
        title: String,
        subtitle: String,
        strongOrCredential: Boolean = false
    ): Boolean {
        return kotlinx.coroutines.suspendCancellableCoroutine { cont ->
            val cancel = android.os.CancellationSignal()
            val builder = android.hardware.biometrics.BiometricPrompt.Builder(activity)
                .setTitle(title)
                .setSubtitle(subtitle)
            if (strongOrCredential && android.os.Build.VERSION.SDK_INT >= 30) {
                builder.setAllowedAuthenticators(
                    android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
                        or android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL)
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
