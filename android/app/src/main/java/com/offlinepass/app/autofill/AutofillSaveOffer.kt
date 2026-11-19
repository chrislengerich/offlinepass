package com.offlinepass.app.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * THE SAVE OFFER (the "if confirmed" gate): the notification → MainActivity's
 * AddEntry prefilled — the app's FULL save machinery runs there (the gate,
 * the commit signer, the touch prompt); no duplicated save path. Posted by:
 * - the auth activity's GENERATE mode (the generated password — the OS's
 *   onSaveRequest SUPPRESSES the autofilled values, so the offer must be
 *   self-posted), and
 * - onSaveRequest (the user-typed logins — the platform's own trigger).
 * The password rides the intent (the app's own process; never the
 * notification text).
 */
object AutofillSaveOffer {

    const val EXTRA_SAVE_NAME = "autofill-save-name"
    const val EXTRA_SAVE_USERNAME = "autofill-save-username"
    const val EXTRA_SAVE_PASSWORD = "autofill-save-password"

    private var requestCode = 4000
    private var notifId = 4001

    fun post(context: Context, origin: String, username: String?, password: String) {
        val nm = context.getSystemService(android.app.NotificationManager::class.java)
        // THE HEADS-UP BANNER: the offer must INTERRUPT the form (the old
        // channel ran at DEFAULT = tray-only — the user never saw it; the
        // channel's importance = frozen at the first creation, so the NEW
        // id + HIGH). The banner = the "if confirmed" moment itself.
        val channelId = "autofill-save-hi"
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(android.app.NotificationChannel(
                channelId, "Autofill save offers",
                android.app.NotificationManager.IMPORTANCE_HIGH).apply {
                enableVibration(true)
            })
        }
        val granted = if (android.os.Build.VERSION.SDK_INT >= 33) {
            context.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
        } else true
        if (!granted) {
            Log.w("OfflinepassAutofill",
                "the save offer for $origin could not be posted — POST_NOTIFICATIONS not granted")
            return
        }
        val intent = Intent(context, com.offlinepass.app.MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            .putExtra(EXTRA_SAVE_NAME, origin)
            .putExtra(EXTRA_SAVE_USERNAME, username ?: "")
            .putExtra(EXTRA_SAVE_PASSWORD, password)
        val pi = PendingIntent.getActivity(
            context, requestCode++, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = androidx.core.app.NotificationCompat.Builder(context, channelId)
            .setSmallIcon(com.offlinepass.app.R.mipmap.ic_launcher)
            .setContentTitle("Save this login to offlinepass?")
            .setContentText(origin + (username?.let { " — $it" } ?: ""))
            .setContentIntent(pi)
            .setPriority(androidx.core.app.NotificationCompat.PRIORITY_HIGH)
            .setVibrate(longArrayOf(0, 250, 150, 250))
            .setAutoCancel(true)
            .build()
        nm.notify(notifId++, n)
        Log.i("OfflinepassAutofill", "the save offer posted for $origin " +
            "(username=${!username.isNullOrBlank()})")
    }
}
