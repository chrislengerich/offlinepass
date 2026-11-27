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

    /** THE AUTH PENDINGINTENT FLAGS (Proton Pass's shape): MUTABLE +
     *  CANCEL_CURRENT on S+ — the mutable binding lets the framework's
     *  fill-in intent merge, and CANCEL_CURRENT rebinds fresh per send. */
    private val authPendingIntentFlags: Int =
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            android.app.PendingIntent.FLAG_MUTABLE or
                android.app.PendingIntent.FLAG_CANCEL_CURRENT
        } else {
            android.app.PendingIntent.FLAG_CANCEL_CURRENT
        }

    data class Fields(
        val username: List<AutofillId>,
        /** THE EMAIL BUCKET (the tier-1 email-marked fields) — split from
         *  the username bucket so a signup with BOTH boxes fills each
         *  with its own value (the measured single-bucket wrongness: the
         *  email box received the username whenever they differed). */
        val email: List<AutofillId> = emptyList(),
        val password: List<AutofillId>,
        val appPackage: String,
        val webDomain: String?,
        /** The first non-empty text currently in the fields (the save
         *  request's capture; the fill requests leave them null). */
        val usernameValue: String? = null,
        val passwordValue: String? = null
    ) {
        /** Every identity-side id (the username + the email buckets) —
         *  the save-info targets and the "any fillable field" checks. */
        val allIdentityIds: List<AutofillId> get() = username + email

        /** The page-match predicate (the generate-chips' offer condition,
         *  shared with the ranking) — the PRECISE origin rule
         *  (OriginMatch), not the old substring. */
        fun matches(item: ProtonItem): Boolean =
            OriginMatch.rank(item, webDomain, appPackage) > 0
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
        // THE SELF-FILL GUARD: the activity's fields are excluded at the
        // view level (the decorView's NO_EXCLUDE_DESCENDANTS) — this
        // belt-and-suspenders the loop: the service never answers a fill
        // request for its OWN package.
        if (fields.appPackage == packageName) {
            callback.onSuccess(null); return
        }
        // No recognized login fields → no response. Building a dataset with
        // zero values throws — and this service shares the app's process, so
        // a crash here kills the whole app (vault session included).
        if (fields.username.isEmpty() && fields.email.isEmpty() && fields.password.isEmpty()) {
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
        val allIds = fields.allIdentityIds.plus(fields.password).toTypedArray()
        if (allIds.isEmpty()) return this
        return setSaveInfo(android.service.autofill.SaveInfo.Builder(
            android.service.autofill.SaveInfo.SAVE_DATA_TYPE_PASSWORD or
                android.service.autofill.SaveInfo.SAVE_DATA_TYPE_USERNAME or
                android.service.autofill.SaveInfo.SAVE_DATA_TYPE_EMAIL_ADDRESS,
            allIds
        ).build())
    }

    /** THE PER-DATASET RESILIENCE: a single dataset's build failure (the
     *  zero-field IllegalStateException class — the measured mail.proton.me
     *  alias chip) skips THAT dataset; the sheet's other entries survive.
     *  The old whole-response catch degraded EVERY suggestion to none. A
     *  null from the maker = the maker's own skip decision (it logs). */
    private fun FillResponse.Builder.addDatasetSafe(make: () -> Dataset?) {
        val ds = try { make() } catch (e: Exception) {
            Log.w(TAG, "a dataset build failed — the chip is skipped " +
                "(the sheet survives): ${e.message}")
            null
        }
        ds?.let { addDataset(it) }
    }

    private fun unlockedResponse(fields: Fields): FillResponse {
        val items = (VaultSession.state as? VaultSession.State.Unlocked)?.items ?: emptyList()
        Log.i(TAG, "branch=unlocked pkg=${fields.appPackage} domain=${fields.webDomain} " +
            "items=${items.size}")
        // Rank: URL/domain match first, then everything else (the precise
        // origin rule — OriginMatch).
        val ranked = items.sortedByDescending { item ->
            OriginMatch.rank(item, fields.webDomain, fields.appPackage)
        }

        val builder = FillResponse.Builder()
        val shown = ranked.take(5)
        for (item in shown) {
            builder.addDatasetSafe {
                datasetFor(item, fields, "${item.displayName} — ${item.identity}")
            }
        }
        // THE GENERATE CHIP: offered on EVERY password field (the user's
        // call — the generate option must never be missing). Tapping
        // gates, generates, and the fill rides the auth result.
        if (passwordChipOffered(fields, shown)) {
            builder.addDatasetSafe { generateDataset(fields) }
        }
        // THE ALIAS CHIP (the email fields' generate): offered on ANY form
        // with a username/email field (not registration-only — the second
        // account on a matched site works too), only with the SL link
        // (the creation needs the api key). The dataset carries the
        // username/email ids, so it surfaces when an email field is
        // focused.
        if (aliasChipOffered(fields, VaultSession.simpleLoginItem() != null)) {
            builder.addDatasetSafe { generateAliasDataset(fields) }
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
        (fields.allIdentityIds + fields.password).firstOrNull()?.let {
            searchDs.setValue(it, null as AutofillValue?, searchView)
        }
        builder.addDatasetSafe { searchDs.build() }
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
            "(datasetId=${revealedId?.take(8) ?: "none"}) ids=" +
            "${fields.username.size}+${fields.email.size}u/${fields.password.size}p")
        // Rank: the URL/domain match first, then everything else (the
        // precise origin rule — OriginMatch).
        val ranked = manifest.sortedByDescending { item ->
            OriginMatch.rank(item, fields.webDomain, fields.appPackage)
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
            builder.addDatasetSafe {
                datasetFor(
                    revealed, fields,
                    "✓ ${revealed.displayName} — ${revealed.identity}",
                    revealedId ?: revealed.itemUuid)
            }
            count++
            Log.i(TAG, "revealed dataset: id=${revealedId ?: revealed.itemUuid} " +
                "identity=${revealed.identity} pwLen=${revealed.password.length} " +
                "usernameIds=${fields.username.size} passwordIds=${fields.password.size}")
        }
        val ids = fields.allIdentityIds + fields.password
        var requestCode = 10
        // THE ⚡ CHIP: the password-focused sheets — the registration case.
        builder.addDatasetSafe { generateDataset(fields, requestCode++) }
        count++
        // THE ✨ CHIP: the alias + password generate (the SL link required
        // — the slUuid carries the sealed cache's key entry for the
        // flow's gated reveal). The dataset carries the username ids, so
        // it surfaces when an email/username field is focused.
        builder.addDatasetSafe { generateAliasDataset(fields, requestCode++, slUuid) }
        count++
        for (item in ranked.take(5)) {
            if (revealed != null && item.itemUuid == revealed.itemUuid) continue
            val intent = android.content.Intent(appContext(), AutofillAuthActivity::class.java)
                .putExtra(AutofillAuthActivity.EXTRA_UUID, item.itemUuid)
                // THE FILL TARGETS: the reveal's auth result carries the
                // filled dataset (the docs' CVC pattern — the same shape
                // the generate chips use) — the ids it must fill.
                .putParcelableArrayListExtra(
                    AutofillAuthActivity.EXTRA_FILL_USERNAME_IDS, ArrayList(fields.username))
                .putParcelableArrayListExtra(
                    AutofillAuthActivity.EXTRA_FILL_EMAIL_IDS, ArrayList(fields.email))
                .putParcelableArrayListExtra(
                    AutofillAuthActivity.EXTRA_FILL_PASSWORD_IDS, ArrayList(fields.password))
                // NO FLAG_ACTIVITY_NEW_TASK — the for-result delivery (the
                // same reasoning as generateIntent).
            val pi = android.app.PendingIntent.getActivity(
                appContext(), requestCode++, intent, authPendingIntentFlags)
            val view = RemoteViews(packageName, R.layout.autofill_item).apply {
                setTextViewText(R.id.autofill_text, sealedLabel(item))
            }
            val ds = Dataset.Builder().setAuthentication(pi.intentSender)
                .setId(item.itemUuid)
            ids.forEach { id -> ds.setValue(id, AutofillValue.forText(""), view) }
            builder.addDatasetSafe { ds.build() }
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
        val builder = FillResponse.Builder()
        // THE GENERATE CHIPS: offered in EVERY state — the generation and
        // the fill never need the vault unlocked. The save may not land
        // here (a key-locked vault needs the app's unlock first) — the
        // toast reports that honestly, and the filled password can be
        // saved manually after the app's own unlock.
        builder.addDatasetSafe { generateDataset(fields, 30) }
        builder.addDatasetSafe { generateAliasDataset(fields, 40) }
        val intent = android.content.Intent(appContext(), MainActivity::class.java)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val pi = android.app.PendingIntent.getActivity(
            appContext(), 0, intent,
            android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT
        )
        val view = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_text, "🔒 Unlock offlinepass (touch key), then autofill again")
        }
        val ids = fields.allIdentityIds + fields.password
        val ds = Dataset.Builder()
        ids.forEach { id -> ds.setValue(id, AutofillValue.forText(""), view) }
        ds.setAuthentication(pi.intentSender)
        builder.addDatasetSafe { ds.build() }
        return builder.withSaveInfo(fields).build()
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
        // THE ONE FILL RULE (fillPairs): the identity → the username ids,
        // the item's email (identity fallback) → the email ids, the
        // password → the password ids; blanks fill nothing.
        fillPairs(fields.username, fields.email, fields.password, item).forEach { (id, value) ->
            ds.setValue(id, AutofillValue.forText(value), view)
        }
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
                AutofillAuthActivity.EXTRA_FILL_EMAIL_IDS, ArrayList(fields.email))
            .putParcelableArrayListExtra(
                AutofillAuthActivity.EXTRA_FILL_PASSWORD_IDS, ArrayList(fields.password))
            // NO FLAG_ACTIVITY_NEW_TASK: the framework starts the auth
            // PendingIntent FOR RESULT (startIntentSenderForResult) — the
            // new-task launch ABORTS on the first attempt (the measured
            // instant CANCELED result 9ms in, before onCreate) and the
            // spurious result consumes the framework's auth tracking —
            // the real RESULT_OK at the finish then has no recipient and
            // the session stays WAITING_FOR_AUTH forever. The in-task
            // launch (translucent over the browser) delivers the result.

    internal fun generateDataset(fields: Fields, requestCode: Int = 30): Dataset? {
        if (fields.password.isEmpty()) {
            Log.i(TAG, "generate chip skipped — no password field detected")
            return null
        }
        val origin = fields.webDomain ?: fields.appPackage
        val intent = generateIntent(AutofillAuthActivity.MODE_GENERATE, origin, fields)
            .putExtra(AutofillAuthActivity.EXTRA_USERNAME, fields.usernameValue ?: "")
        val pi = android.app.PendingIntent.getActivity(
            appContext(), requestCode, intent, authPendingIntentFlags)
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
        fields.allIdentityIds.isNotEmpty() && slReachable

    /** The SL entry's uuid in the SEALED manifest, or null. The manifest
     *  items carry name/urls in the clear (the passwords stay sealed), so
     *  the detection = the app.simplelogin.io URL — the same marker the
     *  link flow writes (the ONE predicate: VaultSession.isSimpleLoginUrl). */
    internal fun sealedSimpleLoginUuid(): String? =
        SealedVault.manifestItems().firstOrNull { item ->
            item.urls.any { VaultSession.isSimpleLoginUrl(it) }
        }?.itemUuid

    /** The "✨ Generate SimpleLogin alias + password" dataset: the auth =
     *  the auth activity's GENERATE_ALIAS mode (the screenlock gates, the
     *  SL chain creates the alias on the linked account); the fill = the
     *  alias into the username/email ids AND the generated password into
     *  the password ids — the full signup fill in one tap. Offered only
     *  when the SimpleLogin is linked. Null when no username/email field
     *  exists. */
    internal fun generateAliasDataset(
        fields: Fields, requestCode: Int = 40, slUuid: String? = null
    ): Dataset? {
        // THE ALIAS FILLS BOTH IDENTITY BUCKETS (the alias IS an email —
        // the email-marked boxes get it too), so the placeholders surface
        // the chip on either box's focus.
        val ids = fields.allIdentityIds
        if (ids.isEmpty()) {
            Log.i(TAG, "alias chip skipped — no username/email field detected")
            return null
        }
        val origin = fields.webDomain ?: fields.appPackage
        val intent = generateIntent(AutofillAuthActivity.MODE_GENERATE_ALIAS, origin, fields)
        slUuid?.let { intent.putExtra(AutofillAuthActivity.EXTRA_SL_UUID, it) }
        val pi = android.app.PendingIntent.getActivity(
            appContext(), requestCode, intent, authPendingIntentFlags)
        val view = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_text, "✨ Generate SimpleLogin alias + password")
        }
        val ds = Dataset.Builder().setAuthentication(pi.intentSender)
            .setId("generate_alias")
        // THE PLACEHOLDERS = NULL (the docs' CVC pattern — the empty
        // strings mark the views CHANGED and pollute the session state).
        // THE IDENTITY IDS ONLY (both buckets — the email box alone must
        // surface AND hold the chip: a placeholder loop over the username
        // bucket alone produced a ZERO-field dataset on the email-only
        // pages and build() threw, degrading the WHOLE response to no
        // suggestions — the measured mail.proton.me no-sheet). The
        // password ids stay out (the ⚡ chip owns password-focused
        // fields). The FILL still covers every bucket — the auth result's
        // dataset carries the alias AND the password.
        for (id in ids) ds.setValue(id, null, view)
        Log.i(TAG, "alias chip offered for $origin (id=generate_alias)")
        return ds.build()
    }

    internal fun parse(structure: AssistStructure): Fields = parseAutofillStructure(structure)

    private fun appContext() = applicationContext
}

/**
 * THE FORM PARSER — shared between the autofill service (the fill
 * requests) and the auth activity (the auth launch's fill-in intent
 * carries the LATEST AssistStructure once the PendingIntent is mutable,
 * and the activity re-parses it to read the fields' CURRENT values — the
 * user may have typed since the fill request).
 */
internal fun parseAutofillStructure(
    structure: AssistStructure
): OfflinepassAutofillService.Fields {
    val username = mutableListOf<AutofillId>()
    val email = mutableListOf<AutofillId>()
    val password = mutableListOf<AutofillId>()
    var usernameValue: String? = null
    var passwordValue: String? = null
    var appPackage = structure.activityComponent.packageName
    var webDomain: String? = null
    // THE TIERED USERNAME CAPTURE: the explicitly-marked email/username
    // fields (tier 1) always beat the loose-substring matches (tier 2) —
    // the login/SSO forms embed auxiliary fields (userToken,
    // loginChallenge) that match the loose substrings and would win the
    // first-non-blank race otherwise.
    var strongUsernameValue: String? = null
    var strongUsernameFrom: String? = null
    var weakUsernameValue: String? = null
    var weakUsernameFrom: String? = null

    /** The tiered capture, shared by both identity buckets (the save's
     *  usernameValue and the generate chips' typed username ride it
     *  regardless of which bucket the field landed in). */
    fun captureIdentityValue(node: AssistStructure.ViewNode, strong: Boolean) {
        (node.autofillValue?.textValue as? CharSequence)
            ?.takeIf { it.isNotBlank() && !it.startsWith("http") && !it.startsWith("www.") }
            ?.let { v ->
                val value = v.toString()
                val from = (node.idEntry ?: "").lowercase().ifBlank { node.hint?.lowercase() ?: "" }
                if (strong) {
                    if (strongUsernameValue == null) {
                        strongUsernameValue = value
                        strongUsernameFrom = from
                    }
                } else if (weakUsernameValue == null) {
                    weakUsernameValue = value
                    weakUsernameFrom = from
                }
            }
    }

    fun walk(node: AssistStructure.ViewNode) {
        node.webDomain?.let { if (webDomain == null) webDomain = it }
        val hints = node.autofillHints?.joinToString(" ")?.lowercase() ?: ""
        val hint = node.hint?.lowercase() ?: ""
        val resId = (node.idEntry ?: "").lowercase()
        // THE URL-SHAPED FIELDS ARE NEVER USERNAMES: the login/SSO forms
        // embed hidden fields carrying the page URL (loginUrl, returnUrl,
        // accountRedirect) whose ids/hints match the loose username
        // substrings — the captured username would be the page URL.
        val looksLikeUrlField = resId.contains("url") || hint.contains("url") ||
            resId.contains("redirect") || hint.contains("redirect")
        val isPassword = node.autofillHints?.contains(View.AUTOFILL_HINT_PASSWORD) == true ||
            hints.contains("password") || hint.contains("password") ||
            resId.contains("password") || resId.contains("passwd") ||
            (node.inputType and (android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD)) ==
            (android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD)
        // TIER 1: the explicit marks — the autofill hints, the email
        // anywhere, the username in the id/hint.
        val explicitEmail = node.autofillHints?.any {
            it.contains("email", ignoreCase = true)
        } == true || hints.contains("email") || hint.contains("email") ||
            resId.contains("email")
        val explicitUsername = node.autofillHints?.any {
            it.contains("username", ignoreCase = true)
        } == true || hints.contains("username") || resId.contains("username")
        val isIdentity = !isPassword && !looksLikeUrlField && (
            explicitEmail || explicitUsername ||
                node.autofillHints?.contains(View.AUTOFILL_HINT_USERNAME) == true ||
                hint.contains("user") || resId.contains("user") ||
                resId.contains("login") || resId.contains("account")
            )
        // THE BUCKET SPLIT: an explicitly-EMAIL field (and nothing else
        // about it marked username) goes to the email bucket; a dual-
        // marked field (both user and email hints) stays in the username
        // bucket — the old single-bucket behavior for the ambiguous shape.
        val isEmailField = isIdentity && explicitEmail && !explicitUsername
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
                    // THE VALUE CAPTURE runs for BOTH identity buckets —
                    // the save path's usernameValue (an email-only form's
                    // email IS the login's username) and the generate
                    // chips' typed-username ride it regardless of bucket.
                    isEmailField -> {
                        email.add(id)
                        captureIdentityValue(node, explicitEmail || explicitUsername)
                    }
                    isIdentity -> {
                        username.add(id)
                        captureIdentityValue(node, explicitEmail || explicitUsername)
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
    usernameValue = strongUsernameValue ?: weakUsernameValue
    Log.d("OfflinepassAutofill", "the username capture: tier=${if (strongUsernameValue != null) 1 else 2} " +
        "value=${usernameValue?.length ?: 0} chars " +
        "from=${strongUsernameFrom ?: weakUsernameFrom ?: "none"} " +
        "(username fields: ${username.size})")
    return OfflinepassAutofillService.Fields(
        username = username,
        email = email,
        password = password,
        appPackage = appPackage,
        webDomain = webDomain,
        usernameValue = usernameValue,
        passwordValue = passwordValue)
}

/** THE FILL PAIRS — the ONE rule both the sheet's datasets and the
 *  auth-result dataset follow (the single source of truth for which id
 *  gets which value):
 *  - the username ids get the identity (username-first, the email as the
 *    fallback — the dedup key's shape);
 *  - the EMAIL ids get the item's EMAIL, falling back to the identity
 *    (an email-only item's identity IS its email);
 *  - the password ids always get the password (the historical semantics —
 *    a password field is the item's password, blank or not);
 *  - a blank value fills NOTHING (the no-clobber rule — the user's typed
 *    text survives).
 *  Empty result = the caller offers no dataset (the zero-value build()
 *  throw — the measured process-killer — stays unreachable). */
internal fun fillPairs(
    usernameIds: List<AutofillId>?,
    emailIds: List<AutofillId>?,
    passwordIds: List<AutofillId>?,
    item: ProtonItem
): List<Pair<AutofillId, String>> = buildList {
    if (item.identity.isNotBlank()) {
        usernameIds.orEmpty().forEach { add(it to item.identity) }
    }
    val emailValue = item.email.ifBlank { item.identity }
    if (emailValue.isNotBlank()) {
        emailIds.orEmpty().forEach { add(it to emailValue) }
    }
    passwordIds.orEmpty().forEach { add(it to item.password) }
}
