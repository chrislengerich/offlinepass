package com.offlinepass.app.autofill

import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.service.autofill.*
import android.util.Log
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.offlinepass.app.MainActivity
import com.offlinepass.app.R
import com.offlinepass.app.vault.ProtonItem
import com.offlinepass.app.vault.SealedVault
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

    private val TAG = "OfflinepassAutofill"

    data class Fields(
        val username: List<AutofillId>,
        val password: List<AutofillId>,
        val appPackage: String,
        val webDomain: String?,
        /** The first non-empty text currently in the fields (the save
         *  request's capture; the fill requests leave them null). */
        val usernameValue: String? = null,
        val passwordValue: String? = null
    ) {
        /** The page-match predicate (the ranking's match rule, shared with
         *  the generate-chip's offer condition). */
        fun matches(item: ProtonItem): Boolean =
            (webDomain != null && item.urls.any { url ->
                url.contains(webDomain!!.removePrefix("www."))
            }) || item.urls.any { url -> url.contains(appPackage) }
    }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        VaultSession.init(applicationContext)
        // The service's process may be freshly spawned (a crash-restart):
        // the SealedVault's lateinit appContext must be initialized before
        // any manifest/cache read (the measured UninitializedPropertyAccess).
        SealedVault.init(applicationContext)
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

        // THE SERVICE MUST NEVER THROW INTO THE FRAMEWORK — it shares the
        // app's process, so a throw here = the vault session dies with it
        // (the measured crash: a zero-value dataset's build() on the
        // password-less Google page). Any response bug degrades to no
        // suggestions instead of a process kill.
        val response = try {
            when {
                // The sealed/stub states: the targeted single-item unseal (the
                // screenlock gate) — the stub session's memory holds no secrets,
                // so the unseal branch must win over the unlocked branch.
                VaultSession.screenlockUnlockEnabled() &&
                    SealedVault.manifestItems().isNotEmpty() -> sealedResponse(fields)
                VaultSession.state is VaultSession.State.Unlocked -> unlockedResponse(fields)
                else -> lockedResponse(fields)
            }
        } catch (e: Exception) {
            Log.e(TAG, "the fill response failed — degrading to no suggestions", e)
            null
        }
        callback.onSuccess(response)
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        VaultSession.init(applicationContext)
        SealedVault.init(applicationContext)
        val structure = request.fillContexts.lastOrNull()?.structure
        val fields = structure?.let { parse(it) }
        val pw = fields?.passwordValue
        if (pw.isNullOrBlank()) {
            Log.i(TAG, "onSaveRequest: no password captured — ignoring " +
                "(pkg=${fields?.appPackage})")
            callback.onFailure("offlinepass: no password in the form")
            return
        }
        val origin = fields?.webDomain ?: fields?.appPackage ?: "the login"
        // THE INTERSTITIAL, LAUNCHED BY THE FRAMEWORK: the save UI runs
        // AFTER the login completed (the user's sequencing) — the screenlock
        // gate → the question → the save, all in the auth activity. The
        // values ride the intent (the app's own process).
        val intent = android.content.Intent(appContext(), AutofillAuthActivity::class.java)
            .putExtra(AutofillAuthActivity.EXTRA_MODE, AutofillAuthActivity.MODE_SAVE)
            .putExtra(AutofillAuthActivity.EXTRA_NAME, origin)
            .putExtra(AutofillAuthActivity.EXTRA_USERNAME, fields?.usernameValue ?: "")
            .putExtra(AutofillAuthActivity.EXTRA_PASSWORD, pw)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        val pi = android.app.PendingIntent.getActivity(
            appContext(), 500, intent,
            android.app.PendingIntent.FLAG_IMMUTABLE or
                android.app.PendingIntent.FLAG_UPDATE_CURRENT)
        Log.i(TAG, "onSaveRequest: the save interstitial armed for $origin " +
            "(username=${!fields?.usernameValue.isNullOrBlank()})")
        callback.onSuccess(pi.intentSender)
    }

    /** THE SAVE CONTRACT: the declared savable fields — without this the
     *  framework never fires onSaveRequest on the activity's finish (the
     *  measured missing save-offer). The username = optional (the signup
     *  forms may leave it blank), the password = required. The flag =
     *  the save fires when ALL the autofillable views go invisible (the
     *  form's dismissal) — the experiment for the username-less signups
     *  (the all-autofilled case: the framework's default = the save only
     *  when a user-entered field changed). */
    private fun FillResponse.Builder.withSaveInfo(fields: Fields): FillResponse.Builder {
        val allIds = (fields.username + fields.password).toTypedArray()
        if (allIds.isEmpty()) return this
        return setFlags(FillResponse.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
            .setSaveInfo(android.service.autofill.SaveInfo.Builder(
                android.service.autofill.SaveInfo.SAVE_DATA_TYPE_PASSWORD or
                    android.service.autofill.SaveInfo.SAVE_DATA_TYPE_USERNAME,
                allIds
            ).build())
    }

    private fun unlockedResponse(fields: Fields): FillResponse {
        val items = (VaultSession.state as? VaultSession.State.Unlocked)?.items ?: emptyList()
        Log.i(TAG, "branch=unlocked pkg=${fields.appPackage} domain=${fields.webDomain} " +
            "items=${items.size}")
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
        // THE GENERATE CHIP: the registration / new-credentials case — no
        // entry matches the page. Tapping gates, generates, and the
        // re-invoke fills the fresh password. Only WITH a password field
        // (a zero-value dataset = the platform build() throws).
        if (shown.none { fields.matches(it) }) {
            generateDataset(fields)?.let { builder.addDataset(it) }
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
        return builder.withSaveInfo(fields).build()
    }

    /** The sealed state: the manifest entries as authenticated datasets —
     *  tapping launches the auth activity (the device credential), which
     *  unseals that ONE item and returns RESULT_OK; the framework then
     *  re-invokes onFillRequest. THE LAYERED RESPONSE: the freshly
     *  revealed item's REAL-value dataset is PREPENDED to the full
     *  manifest list — the re-invoke fills the tapped item AND keeps
     *  every other entry offered (the old short-circuit collapsed the
     *  second interaction to one entry). */
    private fun sealedResponse(fields: Fields): FillResponse {
        val revealed = AutofillRevealStore.peek()
        val revealedId = AutofillRevealStore.peekDatasetId()
        val manifest = SealedVault.manifestItems()
        Log.i(TAG, "branch=sealed pkg=${fields.appPackage} domain=${fields.webDomain} " +
            "manifest=${manifest.size} revealed=${revealed?.displayName ?: "none"} " +
            "(datasetId=${revealedId?.take(8) ?: "none"})")
        // Rank: the URL/domain match first, then everything else.
        val ranked = manifest.sortedByDescending { item ->
            when {
                fields.webDomain != null && item.urls.any { url ->
                    url.contains(fields.webDomain!!.removePrefix("www."))
                } -> 2
                item.urls.any { url -> url.contains(fields.appPackage) } -> 1
                else -> 0
            }
        }
        val builder = FillResponse.Builder()
        var count = 0
        // The revealed item's REAL dataset FIRST — with the SAME dataset
        // ID as its sealed chip: the framework matches the authenticated
        // dataset by ID across the re-invocation and AUTO-FILLS the
        // values (no sheet re-show, no second tap — the measured 25s
        // dead gap + the re-offered sheet).
        if (revealed != null) {
            builder.addDataset(datasetFor(
                revealed, fields,
                "✓ ${revealed.displayName} — ${revealed.identity}",
                revealedId ?: revealed.itemUuid))
            count++
        }
        val ids = (fields.username + fields.password)
        var requestCode = 10
        // THE GENERATE CHIP: no entry matches the page (the registration
        // case) — the tap gates, generates, the re-invoke fills.
        if (ranked.none { fields.matches(it) }) {
            generateDataset(fields, requestCode++)?.let { builder.addDataset(it) }
            count++
        }
        for (item in ranked.take(5)) {
            if (revealed != null && item.itemUuid == revealed.itemUuid) continue
            val intent = android.content.Intent(appContext(), AutofillAuthActivity::class.java)
                .putExtra(AutofillAuthActivity.EXTRA_UUID, item.itemUuid)
                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
            val pi = android.app.PendingIntent.getActivity(
                appContext(), requestCode++, intent,
                android.app.PendingIntent.FLAG_IMMUTABLE or
                    android.app.PendingIntent.FLAG_UPDATE_CURRENT)
            val view = RemoteViews(packageName, R.layout.autofill_item).apply {
                setTextViewText(R.id.autofill_text,
                    "🔒 ${item.displayName} — tap, unlock, fill")
            }
            val ds = Dataset.Builder().setAuthentication(pi.intentSender)
                .setId(item.itemUuid)
            ids.forEach { id -> ds.setValue(id, AutofillValue.forText(""), view) }
            builder.addDataset(ds.build())
            count++
        }
        // The unsealed/not-sealed fallback: the open-the-app dataset.
        val intent = android.content.Intent(appContext(), MainActivity::class.java)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK or
                android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val pi = android.app.PendingIntent.getActivity(
            appContext(), 0, intent,
            android.app.PendingIntent.FLAG_IMMUTABLE or
                android.app.PendingIntent.FLAG_UPDATE_CURRENT)
        val view = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_text, "🔒 Unlock offlinepass (touch key), then autofill again")
        }
        val ds = Dataset.Builder().setAuthentication(pi.intentSender)
            .setId("app")
        ids.forEach { id -> ds.setValue(id, AutofillValue.forText(""), view) }
        builder.addDataset(ds.build())
        Log.i(TAG, "sealed response: $count entry datasets + the app fallback")
        return builder.withSaveInfo(fields).build()
    }

    private fun lockedResponse(fields: Fields): FillResponse {
        Log.i(TAG, "branch=locked pkg=${fields.appPackage} domain=${fields.webDomain}")
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
        return FillResponse.Builder().addDataset(ds.build()).withSaveInfo(fields).build()
    }

    private fun datasetFor(
        item: ProtonItem,
        fields: Fields,
        label: String,
        /** The dataset id — the framework's re-invocation matches the
         *  authenticated dataset by ID (the auto-fill after the auth). */
        id: String? = null
    ): Dataset {
        val view = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_text, label)
        }
        val ds = Dataset.Builder()
        id?.let { ds.setId(it) }
        // THE NO-IDENTITY CASE (the generated password): the username ids
        // stay UNSET — the re-invoke must never clobber the user's typed
        // username with an empty value.
        if (item.identity.isNotBlank()) {
            for (id in fields.username) ds.setValue(id, AutofillValue.forText(item.identity), view)
        }
        for (id in fields.password) ds.setValue(id, AutofillValue.forText(item.password), view)
        return ds.build()
    }

    /** The "⚡ Generate a strong password" dataset: the auth = the auth
     *  activity's GENERATE mode (the screenlock gates — the vault is
     *  touched); only the PASSWORD ids carry a placeholder, so the
     *  re-invoke fills the generated value without touching the username.
     *  Null when no password field exists — a zero-value dataset makes
     *  the platform's build() THROW (the measured process-killer on the
     *  password-less Google sign-in page). */
    private fun generateDataset(fields: Fields, requestCode: Int = 30): Dataset? {
        if (fields.password.isEmpty()) {
            Log.i(TAG, "generate chip skipped — no password field detected")
            return null
        }
        val origin = fields.webDomain ?: fields.appPackage
        val intent = android.content.Intent(appContext(), AutofillAuthActivity::class.java)
            .putExtra(AutofillAuthActivity.EXTRA_MODE, AutofillAuthActivity.MODE_GENERATE)
            .putExtra(AutofillAuthActivity.EXTRA_NAME, origin)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        val pi = android.app.PendingIntent.getActivity(
            appContext(), requestCode, intent,
            android.app.PendingIntent.FLAG_IMMUTABLE or
                android.app.PendingIntent.FLAG_UPDATE_CURRENT)
        val view = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_text, "⚡ Generate a strong password")
        }
        val ds = Dataset.Builder().setAuthentication(pi.intentSender)
            .setId("generate")
        fields.password.forEach { id -> ds.setValue(id, AutofillValue.forText(""), view) }
        Log.i(TAG, "generate chip offered for $origin (id=generate)")
        return ds.build()
    }

    private fun parse(structure: AssistStructure): Fields {
        val username = mutableListOf<AutofillId>()
        val password = mutableListOf<AutofillId>()
        var usernameValue: String? = null
        var passwordValue: String? = null
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
                        isPassword -> {
                            password.add(id)
                            if (passwordValue == null) {
                                (node.autofillValue?.textValue as? CharSequence)
                                    ?.takeIf { it.isNotBlank() }?.let { passwordValue = it.toString() }
                            }
                        }
                        isUsername -> {
                            username.add(id)
                            if (usernameValue == null) {
                                (node.autofillValue?.textValue as? CharSequence)
                                    ?.takeIf { it.isNotBlank() }?.let { usernameValue = it.toString() }
                            }
                        }
                    }
                }
                Unit
            }
            for (i in 0 until node.childCount) walk(node.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) {
            walk(structure.getWindowNodeAt(i).rootViewNode)
        }
        return Fields(username, password, appPackage, webDomain, usernameValue, passwordValue)
    }

    private fun appContext() = applicationContext
}
