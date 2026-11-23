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
        // THE CONFIRMED SAVE: onSaveRequest fires only AFTER the user
        // tapped Save on the platform's own dialog (the measured
        // sequence: the dialog → the confirm → this callback) — the
        // dialog WAS the one question. So the armed intent = THE
        // SCREENLOCK ONLY (the CONFIRMED flag skips the card) → the
        // insert. For the generated password the silent tray trigger is
        // cancelled (the save is happening here; the registry guards the
        // double insert if the card's Save also lands).
        AutofillSaveOffer.cancelTrigger(applicationContext)
        val intent = android.content.Intent(appContext(), AutofillAuthActivity::class.java)
            .putExtra(AutofillAuthActivity.EXTRA_MODE, AutofillAuthActivity.MODE_SAVE)
            .putExtra(AutofillAuthActivity.EXTRA_CONFIRMED, true)
            .putExtra(AutofillAuthActivity.EXTRA_NAME, origin)
            .putExtra(AutofillAuthActivity.EXTRA_USERNAME, fields?.usernameValue ?: "")
            .putExtra(AutofillAuthActivity.EXTRA_PASSWORD, pw)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        val pi = android.app.PendingIntent.getActivity(
            appContext(), 500, intent,
            android.app.PendingIntent.FLAG_IMMUTABLE or
                android.app.PendingIntent.FLAG_UPDATE_CURRENT)
        Log.i(TAG, "onSaveRequest: the confirmed save armed for $origin " +
            "(username=${!fields?.usernameValue.isNullOrBlank()}, generated=" +
            "${AutofillRevealStore.peek()?.password == pw})")
        callback.onSuccess(pi.intentSender)
    }

    /** THE SAVE CONTRACT: the declared savable fields — without this the
     *  framework never fires onSaveRequest on the activity's finish (the
     *  measured missing save-offer). The username = optional (the signup
     *  forms may leave it blank), the password = required. NO extra
     *  flags: the save fires on the user-changed fields at the form's
     *  finish (the verified on-device behavior). */
    private fun FillResponse.Builder.withSaveInfo(fields: Fields): FillResponse.Builder {
        val allIds = (fields.username + fields.password).toTypedArray()
        if (allIds.isEmpty()) return this
        return setSaveInfo(android.service.autofill.SaveInfo.Builder(
            android.service.autofill.SaveInfo.SAVE_DATA_TYPE_PASSWORD or
                android.service.autofill.SaveInfo.SAVE_DATA_TYPE_USERNAME or
                android.service.autofill.SaveInfo.SAVE_DATA_TYPE_EMAIL_ADDRESS,
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
        // THE GENERATE CHIP: offered on EVERY password field (the user's
        // call — the generate option must never be missing). Tapping
        // gates, generates, and the fill rides the auth result.
        if (passwordChipOffered(fields, shown)) {
            generateDataset(fields)?.let { builder.addDataset(it) }
        }
        // THE ALIAS CHIP (the email fields' generate): offered on ANY form
        // with a username/email field (not registration-only — the second
        // account on a matched site works too), only with the SL link
        // (the creation needs the api key). The dataset carries the
        // username/email ids, so it surfaces when an email field is
        // focused.
        if (aliasChipOffered(fields, VaultSession.simpleLoginItem() != null)) {
            generateAliasDataset(fields)?.let { builder.addDataset(it) }
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
        // THE EXPERIMENT (the docs' CVC shape) is retired: the
        // single-✨-dataset sheet never fired (focusedIsUsername was never
        // captured by the parse walk) and its shape - the sheet WITHOUT
        // the items - is not the picker the user wants. The ✨ chip is
        // back in the full sealed sheet, below.
        val slUuid = sealedSimpleLoginUuid()

        val builder = FillResponse.Builder()
        var count = 0
        // THE REVEALED ITEM'S REAL DATASET FIRST — with the SAME dataset
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
            Log.i(TAG, "revealed dataset: id=${revealedId ?: revealed.itemUuid} " +
                "identity=${revealed.identity} pwLen=${revealed.password.length} " +
                "usernameIds=${fields.username.size} passwordIds=${fields.password.size}")
        }
        val ids = (fields.username + fields.password)
        var requestCode = 10
        // THE ⚡ CHIP: the password-focused sheets — the registration case.
        generateDataset(fields, requestCode++)?.let { builder.addDataset(it) }
        count++
        // THE ✨ CHIP: the alias + password generate (the SL link required
        // — the slUuid carries the sealed cache's key entry for the
        // flow's gated reveal). The dataset carries the username ids, so
        // it surfaces when an email/username field is focused.
        generateAliasDataset(fields, requestCode++, slUuid)?.let { builder.addDataset(it) }
        count++
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
                setTextViewText(R.id.autofill_text, sealedLabel(item))
            }
            val ds = Dataset.Builder().setAuthentication(pi.intentSender)
                .setId(item.itemUuid)
            ids.forEach { id -> ds.setValue(id, AutofillValue.forText(""), view) }
            builder.addDataset(ds.build())
            count++
        }
        // THE APP FALLBACK is NOT offered here: the sealed sheet's unlock
        // lives in the 🔒 items themselves (tap, unlock, fill) and the
        // chips cover the generate - a standing "Unlock offlinepass"
        // dataset on every field was misplaced noise. It remains the
        // whole point of the LOCKED sheet (no sealed items - nothing
        // else to offer).
        Log.i(TAG, "sealed response: $count entry datasets")
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

    /** THE SEALED CHIP's LABEL: the clear-text identity (the username /
     *  email from the manifest) makes the picker usable without the
     *  unlock — the secrets stay sealed. */
    internal fun sealedLabel(item: ProtonItem): String {
        val id = item.identity.trim()
        return if (id.isNotBlank()) "${item.displayName} — $id"
        else item.displayName
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
    /** THE GENERATE INTENT (shared by the chips): the mode, the origin,
     *  and THE FILL TARGETS — the parcelable field ids the auth activity
     *  needs to return the filled dataset via EXTRA_AUTHENTICATION_RESULT.
     *  The direct apply matters: the browser's log shows the framework
     *  EXPIRES the response when the auth activity covers the window
     *  (onInvisibleForAutofill) and receives our result as an "empty
     *  intent" — the re-invoke fallback then re-offers the generated item
     *  as a chip instead of filling it. */
    internal fun generateIntent(
        mode: String, origin: String, fields: Fields
    ): android.content.Intent =
        android.content.Intent(appContext(), AutofillAuthActivity::class.java)
            .putExtra(AutofillAuthActivity.EXTRA_MODE, mode)
            .putExtra(AutofillAuthActivity.EXTRA_NAME, origin)
            .putParcelableArrayListExtra(
                AutofillAuthActivity.EXTRA_FILL_USERNAME_IDS, ArrayList(fields.username))
            .putParcelableArrayListExtra(
                AutofillAuthActivity.EXTRA_FILL_PASSWORD_IDS, ArrayList(fields.password))

    private fun generateDataset(fields: Fields, requestCode: Int = 30): Dataset? {
        if (fields.password.isEmpty()) {
            Log.i(TAG, "generate chip skipped — no password field detected")
            return null
        }
        val origin = fields.webDomain ?: fields.appPackage
        val intent = generateIntent(AutofillAuthActivity.MODE_GENERATE, origin, fields)
            .putExtra(AutofillAuthActivity.EXTRA_USERNAME, fields.usernameValue ?: "")
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
        // THE AUTH'D DATASET's PLACEHOLDERS = NULL (the docs' CVC pattern):
        // the empty-string values mark the views CHANGED and pollute the
        // session state — the docs' sample passes null.
        fields.password.forEach { id -> ds.setValue(id, null, view) }
        Log.i(TAG, "generate chip offered for $origin (id=generate)")
        return ds.build()
    }

    /** THE ⚡ CHIP: offered on EVERY form with a password field — the
     *  user's call: the generate option must never be missing from a
     *  password field (the matched-entry datasets fill from the vault;
     *  the chip joins them). */
    internal fun passwordChipOffered(fields: Fields, shown: List<ProtonItem>) =
        fields.password.isNotEmpty()

    internal fun aliasChipOffered(fields: Fields, slReachable: Boolean) =
        fields.username.isNotEmpty() && slReachable

    /** The SL entry's uuid in the SEALED manifest, or null. The manifest
     *  items carry name/urls in the clear (the passwords stay sealed), so
     *  the detection = the app.simplelogin.io URL — the same marker the
     *  link flow writes. */
    internal fun sealedSimpleLoginUuid(): String? =
        SealedVault.manifestItems().firstOrNull { item ->
            item.urls.any { url ->
                runCatching {
                    java.net.URI(url.trim()).host?.removePrefix("www.") == VaultSession.SL_HOST
                }.getOrDefault(false)
            }
        }?.itemUuid

    /** The "✨ Generate SimpleLogin alias + password" dataset: the auth =
     *  the auth activity's GENERATE_ALIAS mode (the screenlock gates, the
     *  SL chain creates the alias on the linked account); the fill = the
     *  alias into the username/email ids AND the generated password into
     *  the password ids — the full signup fill in one tap. Offered only
     *  when the SimpleLogin is linked. Null when no username/email field
     *  exists. */
    private fun generateAliasDataset(
        fields: Fields, requestCode: Int = 40, slUuid: String? = null
    ): Dataset? {
        val ids = fields.username
        if (ids.isEmpty()) {
            Log.i(TAG, "alias chip skipped — no username/email field detected")
            return null
        }
        val origin = fields.webDomain ?: fields.appPackage
        val intent = generateIntent(AutofillAuthActivity.MODE_GENERATE_ALIAS, origin, fields)
        slUuid?.let { intent.putExtra(AutofillAuthActivity.EXTRA_SL_UUID, it) }
        intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        val pi = android.app.PendingIntent.getActivity(
            appContext(), requestCode, intent,
            android.app.PendingIntent.FLAG_IMMUTABLE or
                android.app.PendingIntent.FLAG_UPDATE_CURRENT)
        val view = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_text, "✨ Generate SimpleLogin alias + password")
        }
        val ds = Dataset.Builder().setAuthentication(pi.intentSender)
            .setId("generate_alias")
        // THE PLACEHOLDERS = NULL (the docs' CVC pattern — the empty
        // strings mark the views CHANGED and pollute the session state).
        // THE USERNAME IDS ONLY: the placeholders decide where the chip
        // SURFACES — the password ids would offer the alias chip on
        // password-focused fields too (the user's call: the ⚡ chip owns
        // those). The FILL still covers both fields — the auth result's
        // dataset carries the alias AND the password.
        for (id in fields.username) ds.setValue(id, null, view)
        Log.i(TAG, "alias chip offered for $origin (id=generate_alias)")
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
