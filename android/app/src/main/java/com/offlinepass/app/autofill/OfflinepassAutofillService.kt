package com.offlinepass.app.autofill

import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.service.autofill.*
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.offlinepass.app.MainActivity
import com.offlinepass.app.R
import com.offlinepass.app.vault.ProtonItem
import com.offlinepass.app.vault.VaultSession

/**
 * Android Autofill Service (S4). Unlocked: offers matching entries
 * (username into username-ish fields, password into password-ish fields).
 * Locked: a single "Unlock offlinepass" dataset that opens the app; after
 * the key touch the system re-prompts.
 *
 * Field heuristics (Bitwarden/KeePassDX-lite): autofillHints first, then
 * hint text, then resource-id/idEntry substrings.
 */
class OfflinepassAutofillService : AutofillService() {

    data class Fields(
        val username: List<AutofillId>,
        val password: List<AutofillId>,
        val appPackage: String,
        val webDomain: String?
    )

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        VaultSession.init(applicationContext)
        val structure = request.fillContexts.lastOrNull()?.structure ?: run {
            callback.onSuccess(null); return
        }
        val fields = parse(structure)
        // No recognized login fields → no response. Building a dataset with
        // zero values throws — and this service shares the app's process, so
        // a crash here kills the whole app (vault session included).
        if (fields.username.isEmpty() && fields.password.isEmpty()) {
            callback.onSuccess(null); return
        }

        val response = if (VaultSession.state is VaultSession.State.Unlocked) {
            unlockedResponse(fields)
        } else {
            lockedResponse(fields)
        }
        callback.onSuccess(response)
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Capture/save of new credentials is a non-goal (design §3); only
        // filling is supported.
        callback.onFailure("offlinepass does not save new credentials from autofill")
    }

    private fun unlockedResponse(fields: Fields): FillResponse {
        val items = (VaultSession.state as? VaultSession.State.Unlocked)?.items ?: emptyList()
        // Rank: URL/domain match first, then everything else.
        val ranked = items.sortedByDescending { item ->
            when {
                fields.webDomain != null && item.urls.any { url ->
                    url.contains(fields.webDomain!!.removePrefix("www."))
                } -> 2
                item.urls.any { url -> url.contains(fields.appPackage) } -> 1
                else -> 0
            }
        }

        val builder = FillResponse.Builder()
        val shown = ranked.take(5)
        for (item in shown) {
            builder.addDataset(datasetFor(item, fields, "${item.displayName} — ${item.identity}"))
        }
        // Search-in-app dataset (covers non-matching or >5 entries). With the
        // empty-fields guard in onFillRequest, at least one id exists here.
        val searchIntent = android.content.Intent(appContext(), MainActivity::class.java)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        val searchPi = android.app.PendingIntent.getActivity(
            appContext(), 1, searchIntent,
            android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT
        )
        val searchView = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_text, "🔎 Search in offlinepass")
        }
        val searchDs = Dataset.Builder()
            .setAuthentication(searchPi.intentSender)
        (fields.username + fields.password).firstOrNull()?.let {
            searchDs.setValue(it, null as AutofillValue?, searchView)
        }
        builder.addDataset(searchDs.build())
        return builder.build()
    }

    private fun lockedResponse(fields: Fields): FillResponse {
        val intent = android.content.Intent(appContext(), MainActivity::class.java)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val pi = android.app.PendingIntent.getActivity(
            appContext(), 0, intent,
            android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT
        )
        val view = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_text, "🔒 Unlock offlinepass (touch key), then autofill again")
        }
        val ids = (fields.username + fields.password)
        val ds = Dataset.Builder()
        ids.forEach { id -> ds.setValue(id, AutofillValue.forText(""), view) }
        ds.setAuthentication(pi.intentSender)
        return FillResponse.Builder().addDataset(ds.build()).build()
    }

    private fun datasetFor(item: ProtonItem, fields: Fields, label: String): Dataset {
        val view = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_text, label)
        }
        val ds = Dataset.Builder()
        for (id in fields.username) ds.setValue(id, AutofillValue.forText(item.identity), view)
        for (id in fields.password) ds.setValue(id, AutofillValue.forText(item.password), view)
        return ds.build()
    }

    private fun parse(structure: AssistStructure): Fields {
        val username = mutableListOf<AutofillId>()
        val password = mutableListOf<AutofillId>()
        var appPackage = structure.activityComponent.packageName
        var webDomain: String? = null

        fun walk(node: AssistStructure.ViewNode) {
            node.webDomain?.let { if (webDomain == null) webDomain = it }
            val hints = node.autofillHints?.joinToString(" ")?.lowercase() ?: ""
            val hint = node.hint?.lowercase() ?: ""
            val resId = (node.idEntry ?: "").lowercase()
            val isPassword = node.autofillHints?.contains(View.AUTOFILL_HINT_PASSWORD) == true ||
                hints.contains("password") || hint.contains("password") ||
                resId.contains("password") || resId.contains("passwd") ||
                (node.inputType and (android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD)) ==
                (android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD)
            val isUsername = !isPassword && (
                node.autofillHints?.contains(View.AUTOFILL_HINT_USERNAME) == true ||
                    hints.contains("username") || hints.contains("email") || hint.contains("email") ||
                    hint.contains("user") || resId.contains("user") || resId.contains("email") ||
                    resId.contains("login") || resId.contains("account")
                )
            node.autofillId?.let { id ->
                if (node.visibility == View.VISIBLE) {
                    when {
                        isPassword -> password.add(id)
                        isUsername -> username.add(id)
                    }
                }
                Unit
            }
            for (i in 0 until node.childCount) walk(node.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) {
            walk(structure.getWindowNodeAt(i).rootViewNode)
        }
        return Fields(username, password, appPackage, webDomain)
    }

    private fun appContext() = applicationContext
}
