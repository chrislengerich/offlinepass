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

    @Volatile private var lastOfferKey: String? = null
    @Volatile private var lastOfferAt: Long = 0

    fun post(context: Context, origin: String, username: String?, password: String) {
        // THE DEDUP: the framework RE-FIRES the save event for the same
        // form (the measured "Shouldn't be logging again" + the double
        // offers) — the same origin+password within 5 minutes = skipped.
        val key = "$origin|${password.hashCode()}"
        val now = System.currentTimeMillis()
        if (key == lastOfferKey && now - lastOfferAt < 5 * 60_000) {
            Log.i("OfflinepassAutofill", "the duplicate save event for $origin — skipped")
            return
        }
        lastOfferKey = key
        lastOfferAt = now
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

    /**
     * THE SILENT TRAY TRIGGER for the generated-password logins: the
     * platform's save event = the user-typed-delta only, so the save
     * question for an all-autofilled submission must be ours. This is
     * NOT the UI — the tray item = silent (the LOW importance: no
     * banner, no vibration); its TAP opens the SAVE-mode bottom card
     * (yes/no → the screenlock → the insert). The username rides along
     * so the card can show it when onSaveRequest updated the offer.
     */
    fun postSilentTrigger(context: Context, origin: String, username: String?, password: String) {
        // The dedup: the same origin+password+username within 5 minutes
        // = the same offer (the username in the key = the update pass).
        val key = "silent|$origin|${password.hashCode()}|${username ?: ""}"
        val now = System.currentTimeMillis()
        if (key == lastOfferKey && now - lastOfferAt < 5 * 60_000) {
            Log.i("OfflinepassAutofill", "the duplicate silent trigger for $origin — skipped")
            return
        }
        lastOfferKey = key
        lastOfferAt = now
        val nm = context.getSystemService(android.app.NotificationManager::class.java)
        // THE QUIET CHANNEL: the LOW importance = the tray only — no
        // heads-up banner, no sound, no vibration.
        val channelId = "autofill-save-quiet"
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(android.app.NotificationChannel(
                channelId, "Autofill save (quiet)",
                android.app.NotificationManager.IMPORTANCE_LOW))
        }
        val granted = if (android.os.Build.VERSION.SDK_INT >= 33) {
            context.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
        } else true
        if (!granted) {
            Log.w("OfflinepassAutofill",
                "the silent trigger for $origin could not be posted — POST_NOTIFICATIONS not granted")
            return
        }
        val intent = Intent(context, AutofillAuthActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            .putExtra(AutofillAuthActivity.EXTRA_MODE, AutofillAuthActivity.MODE_SAVE)
            .putExtra(AutofillAuthActivity.EXTRA_NAME, origin)
            .putExtra(AutofillAuthActivity.EXTRA_USERNAME, username ?: "")
            .putExtra(AutofillAuthActivity.EXTRA_PASSWORD, password)
        val pi = PendingIntent.getActivity(
            context, requestCode++, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = androidx.core.app.NotificationCompat.Builder(context, channelId)
            .setSmallIcon(com.offlinepass.app.R.mipmap.ic_launcher)
            .setContentTitle("Save this login to offlinepass?")
            .setContentText(origin + (username?.let { " — $it" } ?: "") +
                " — tap to review")
            .setContentIntent(pi)
            .setPriority(androidx.core.app.NotificationCompat.PRIORITY_LOW)
            .setAutoCancel(true)
            .build()
        nm.notify(notifId++, n)
        Log.i("OfflinepassAutofill", "the silent trigger posted for $origin " +
            "(username=${!username.isNullOrBlank()})")
    }
}
