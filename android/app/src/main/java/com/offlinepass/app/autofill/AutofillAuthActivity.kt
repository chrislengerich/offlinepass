package com.offlinepass.app.autofill

import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.util.Log
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RemoteViews
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import com.offlinepass.app.R
import com.offlinepass.app.crypto.ScreenlockGate
import com.offlinepass.app.vault.PasswordGen
import com.offlinepass.app.vault.ProtonItem
import com.offlinepass.app.vault.SealedVault
import com.offlinepass.app.simplelogin.SimpleLoginChain
import com.offlinepass.app.simplelogin.SimpleLoginHttp
import com.offlinepass.app.vault.VaultSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The autofill's auth activity, three modes:
 * - **reveal** (default): the sealed-state chip's tapped item — the SAME
 *   screenlock gate as the item view; the TARGETED single item unseals,
 *   the store carries it to the framework's re-invoked onFillRequest.
 *   RESULT_OK = fill; canceled = the picker stays. The unseal NEVER
 *   escapes: the keystore's auth window can lag the device-credential
 *   gate on this ROM (the measured UserNotAuthenticatedException crash)
 *   — the failure = one gate retry, then a clean RESULT_CANCELED.
 * - **generate**: the "⚡ Generate password" chip — the gate, then a
 *   fresh [PasswordGen.password] into the store; RESULT_OK → the fill.
 * - **save**: launched BY THE FRAMEWORK from onSaveRequest — after the
 *   form submission. THE USER'S ORDERING: the question first ("Save
 *   this login to offlinepass?" — one [Save] click), THEN the screenlock
 *   gate, THEN the save (the INSERT path — the autofill's items carry
 *   fresh uuids; no origin matching, no updates).
 *   NO MainActivity navigation in any mode.
 */
class AutofillAuthActivity : ComponentActivity() {

    private var touchDialog: AlertDialog? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        com.offlinepass.app.vault.VaultSession.init(applicationContext)
        com.offlinepass.app.vault.SealedVault.init(applicationContext)
        installPromptSurfaces()
        val mode = intent.getStringExtra(EXTRA_MODE) ?: MODE_REVEAL
        val uuid = intent.getStringExtra(EXTRA_UUID)
        val name = intent.getStringExtra(EXTRA_NAME)
        if (mode == MODE_REVEAL && uuid == null) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }
        lifecycleScope.launch {
            when (mode) {
                MODE_GENERATE_ALIAS -> {
                    // THE ALIAS CHIP'S FLOW: the SL chain (the options →
                    // the account's default-domain suffix → the create,
                    // the hostname = the web origin) → the alias + the
                    // local password → the item fills BOTH the
                    // email/username and the password fields → the
                    // auto-save → the finish delivers the fill.
                    //
                    // NO GATE: the BiometricPrompt's own system UI
                    // activity bubbles an EMPTY result into the
                    // framework's auth tracking the moment it succeeds —
                    // consuming the dataset's authentication before the
                    // flow's filled response can deliver (the measured
                    // onAuthenticationResult(): empty intent). The autofill
                    // only runs on an UNLOCKED phone — the Keyguard
                    // timestamp is already armed by the phone's own
                    // unlock, so the vault operations run quietly.
                    val origin = name?.takeIf { it.isNotBlank() } ?: "Generated login"
                    val generatedPassword = PasswordGen.password()
                    var alias: String? = null
                    var aliasError: String? = null
                    try {
                        // THE EXTRACTED CHAIN (SimpleLoginChainTest pins the
                        // order): the options → the account's DEFAULT-domain
                        // signed suffix → the v3-custom-create with the
                        // default mailbox → the alias. The api key comes
                        // from EITHER state: the unlocked session, or — the
                        // common case, the vault auto-locks — the sealed
                        // cache (the gate ABOVE opened the keystore auth
                        // window, so the reveal is authorized now).
                        val apiKey = resolveSimpleLoginApiKey()
                        alias = SimpleLoginChain.createAlias(
                            SimpleLoginHttp(), apiKey, origin)
                        Log.i(TAG, "the alias created: $alias — the reveal store armed (generate_alias)")
                    } catch (e: Exception) {
                        Log.w(TAG, "the SL alias failed in the alias chip: ${e.message}")
                        aliasError = e.message
                    }
                    val item = ProtonItem(
                        name = origin,
                        email = alias ?: "",
                        username = alias ?: "",
                        urls = listOf("https://$origin"),
                        password = generatedPassword)
                    AutofillRevealStore.put(item, "generate_alias")
                    // THE RESULT-CARRIED FILL: the response rides the
                    // auth result — the framework applies it directly at
                    // the finish, whatever the save card took.
                    val resultIntent = Intent()
                    buildResultResponse(applicationContext, intent,
                        if (item.identity.isNotBlank()) "✓ $origin — ${item.identity}" else "✓ $origin",
                        item)?.let {
                            resultIntent.putExtra(
                                AutofillManager.EXTRA_AUTHENTICATION_RESULT, it)
                        }
                    setResult(RESULT_OK, resultIntent)
                    // THE AUTO-SAVE (the A design): the first gate
                    // authorizes the generation, the fill, AND the save —
                    // the save card + the second gate = the 10-13s delay
                    // that let the framework's autofill session expire
                    // (the measured re-offered chip instead of the fill).
                    // The insert runs IN-FLOW and the finish fires fast —
                    // the 🔒 reveal's proven shape — so the fill applies
                    // directly. The alias is already created remotely:
                    // saving it = the only sane outcome.
                    val updating = VaultSession.upsertTarget(item) != null
                    val r = insertAutofill(origin, item.username, item.password)
                    when (r) {
                        VaultSession.Result.Success ->
                            Toast.makeText(this@AutofillAuthActivity,
                                (if (updating) "Saved ✓ (updated)" else "Saved ✓ (new)") +
                                    (if (aliasError != null) " — the alias failed: $aliasError" else ""),
                                Toast.LENGTH_LONG).show()
                        else ->
                            Toast.makeText(this@AutofillAuthActivity,
                                "The save failed — $r" +
                                    (if (aliasError != null) " — the alias failed: $aliasError" else ""),
                                Toast.LENGTH_LONG).show()
                    }
                    finish()
                    Log.i(TAG, "the alias flow done: alias=$alias updating=$updating r=$r")
                }
                MODE_GENERATE -> {
                    // NO GATE (the same as the alias chip): the prompt's
                    // success bubbles an empty auth result that consumes
                    // the dataset's authentication. The autofill only runs
                    // on an unlocked phone.
                    val origin = name?.takeIf { it.isNotBlank() } ?: "Generated password"
                    // THE PASSWORD ONLY: the generate chip creates NO alias
                    // — the alias = the EMAIL field's chip (✨). The typed
                    // email (the site's field's value at the fill request)
                    // rides the intent — the item and the upsert carry it.
                    val typedEmail = intent.getStringExtra(EXTRA_USERNAME)?.trim().orEmpty()
                    val item = ProtonItem(
                        name = origin,
                        urls = if (origin.contains('.') && !origin.contains(' '))
                            listOf("https://$origin") else emptyList(),
                        email = typedEmail,
                        password = PasswordGen.password())
                    AutofillRevealStore.put(item, "generate")
                    // THE RESULT-CARRIED FILL (the same as the alias chip):
                    // the identity is blank here — the username ids stay
                    // unset (the no-clobber rule), the password fills.
                    val resultIntent = Intent()
                    buildResultResponse(applicationContext, intent,
                        "✓ $origin — the generated password",
                        item)?.let {
                            resultIntent.putExtra(
                                AutofillManager.EXTRA_AUTHENTICATION_RESULT, it)
                        }
                    setResult(RESULT_OK, resultIntent)
                    // THE AUTO-SAVE (the A design — the same as the alias
                    // chip): the insert in-flow, the finish fast, the fill
                    // applies directly. The typed email rides the item.
                    val updating = VaultSession.upsertTarget(item) != null
                    val r = insertAutofill(origin, item.email, item.password)
                    when (r) {
                        VaultSession.Result.Success ->
                            Toast.makeText(this@AutofillAuthActivity,
                                if (updating) "Saved ✓ (updated)" else "Saved ✓ (new)",
                                Toast.LENGTH_LONG).show()
                        else ->
                            Toast.makeText(this@AutofillAuthActivity,
                                "The save failed — $r", Toast.LENGTH_LONG).show()
                    }
                    finish()
                    Log.i(TAG, "the generate flow done: updating=$updating r=$r")
                }
                MODE_SAVE -> {
                    val origin = name?.takeIf { it.isNotBlank() } ?: "Login"
                    if (intent.getBooleanExtra(EXTRA_CONFIRMED, false)) {
                        // THE PLATFORM'S SAVE DIALOG = THE ONE QUESTION
                        // (the user tapped its Save — onSaveRequest fires
                        // only AFTER that confirmation). This launch =
                        // THE SCREENLOCK ONLY: the gate → the insert →
                        // the toast. No card — the card would be the
                        // SECOND question.
                        val gate = ScreenlockGate.promptGate(
                            this@AutofillAuthActivity,
                            "Unlock offlinepass",
                            "The device lock authorizes saving the login")
                        if (!gate) {
                            Log.i(TAG, "the confirmed save's gate declined")
                            Toast.makeText(this@AutofillAuthActivity,
                                "Not saved — the screen lock declined",
                                Toast.LENGTH_LONG).show()
                            setResult(RESULT_OK)
                            finish()
                            return@launch
                        }
                        val saveUsername = intent.getStringExtra(EXTRA_USERNAME) ?: ""
                        val savePassword = intent.getStringExtra(EXTRA_PASSWORD) ?: ""
                        // THE UPDATE-VS-NEW WORDING: the same site +
                        // identity lookup the upsert performs.
                        val saveItem = ProtonItem(
                            name = origin, username = saveUsername,
                            urls = if (origin.contains('.') && !origin.contains(' '))
                                listOf("https://$origin") else emptyList())
                        val updating = VaultSession.upsertTarget(saveItem) != null
                        val r = insertAutofill(origin, saveUsername, savePassword)
                        when (r) {
                            VaultSession.Result.Success -> {
                                Log.i(TAG, "the confirmed save: Saved ✓ " +
                                    "(rev ${VaultSession.currentRev()})")
                                Toast.makeText(this@AutofillAuthActivity,
                                    if (updating) "Updated ✓" else "Saved ✓",
                                    Toast.LENGTH_LONG).show()
                            }
                            else -> {
                                Log.w(TAG, "the confirmed save FAILED: $r")
                                Toast.makeText(this@AutofillAuthActivity,
                                    "The save failed — $r", Toast.LENGTH_LONG).show()
                            }
                        }
                        setResult(RESULT_OK)
                        finish()
                        return@launch
                    }
                    // THE BOTTOM CARD = THE QUESTION: yes/no over the form
                    // (the bottom gravity, ~a quarter up), the outside tap
                    // = the no. [Save] = the screenlock gate → the INSERT
                    // (the URL from the origin, the username optional).
                    // Launched from the silent tray trigger (the
                    // generated-password logins — the platform's save
                    // event = the user-typed-delta only, so the question
                    // must be ours for those).
                    window.setGravity(android.view.Gravity.BOTTOM)
                    window.setLayout(
                        android.view.WindowManager.LayoutParams.MATCH_PARENT,
                        android.view.WindowManager.LayoutParams.WRAP_CONTENT)
                    // THE UPDATE-VS-NEW WORDING (the same lookup).
                    val cardItem = ProtonItem(
                        name = origin, username = intent.getStringExtra(EXTRA_USERNAME) ?: "",
                        urls = if (origin.contains('.') && !origin.contains(' '))
                            listOf("https://$origin") else emptyList())
                    val updating = VaultSession.upsertTarget(cardItem) != null
                    val card = LinearLayout(this@AutofillAuthActivity).apply {
                        orientation = LinearLayout.VERTICAL
                        setPadding(56, 44, 56, 44)
                        background = android.graphics.drawable.GradientDrawable().apply {
                            setColor(0xFF1D1B20.toInt())
                            cornerRadius = 36f
                        }
                    }
                    card.addView(TextView(this@AutofillAuthActivity).apply {
                        text = if (updating) "Update this login in offlinepass?"
                            else "Save this login to offlinepass?"
                        textSize = 17f
                        setTextColor(0xFFFFFFFF.toInt())
                    })
                    card.addView(TextView(this@AutofillAuthActivity).apply {
                        text = origin + (intent.getStringExtra(EXTRA_USERNAME)
                            ?.takeIf { it.isNotBlank() }?.let { " — $it" } ?: "")
                        textSize = 13f
                        setTextColor(0xFFCCC2DC.toInt())
                    })
                    val buttons = LinearLayout(this@AutofillAuthActivity).apply {
                        orientation = LinearLayout.HORIZONTAL
                        gravity = android.view.Gravity.END
                    }
                    buttons.addView(Button(this@AutofillAuthActivity).apply {
                        text = "Not now"
                        setBackgroundColor(0x00000000)
                        setTextColor(0xFFCCC2DC.toInt())
                        setOnClickListener {
                            Log.i(TAG, "the card: the no — done")
                            setResult(RESULT_OK)
                            finish()
                        }
                    })
                    buttons.addView(Button(this@AutofillAuthActivity).apply {
                        text = "Save"
                        setBackgroundColor(0x00000000)
                        setTextColor(0xFFD0BCFF.toInt())
                        setOnClickListener {
                            isEnabled = false
                            lifecycleScope.launch {
                                val gate = ScreenlockGate.promptGate(
                                    this@AutofillAuthActivity,
                                    "Unlock offlinepass",
                                    "The device lock authorizes saving the login")
                                if (!gate) {
                                    Log.i(TAG, "the card save's gate declined")
                                    Toast.makeText(this@AutofillAuthActivity,
                                        "Not saved — the screen lock declined",
                                        Toast.LENGTH_LONG).show()
                                    setResult(RESULT_OK)
                                    finish()
                                    return@launch
                                }
                                val r = insertAutofill(
                                    origin,
                                    intent.getStringExtra(EXTRA_USERNAME) ?: "",
                                    intent.getStringExtra(EXTRA_PASSWORD) ?: "")
                                when (r) {
                                    VaultSession.Result.Success -> {
                                        Log.i(TAG, "the card save: Saved ✓ " +
                                            "(rev ${VaultSession.currentRev()})")
                                        Toast.makeText(this@AutofillAuthActivity,
                                            if (updating) "Updated ✓" else "Saved ✓",
                                            Toast.LENGTH_LONG).show()
                                        setResult(RESULT_OK)
                                        finish()
                                    }
                                    else -> {
                                        Log.w(TAG, "the card save FAILED: $r")
                                        Toast.makeText(this@AutofillAuthActivity,
                                            "The save failed — $r", Toast.LENGTH_LONG).show()
                                        isEnabled = true
                                    }
                                }
                            }
                        }
                    })
                    card.addView(buttons)
                    setContentView(card)
                    // The outside tap = the no.
                    window.decorView.setOnClickListener {
                        Log.i(TAG, "the card: dismissed outside")
                        setResult(RESULT_OK)
                        finish()
                    }
                }
                else -> {
                    // THE REVEAL: the unseal never escapes — the keystore's
                    // window can lag the credential gate (the measured
                    // crash): one gate retry, then the clean cancellation.
                    val gate = ScreenlockGate.promptGate(
                        this@AutofillAuthActivity,
                        "Unlock the entry",
                        "Autofill: the device lock opens this item's secrets")
                    if (!gate) {
                        Log.i(TAG, "auth gate declined — RESULT_CANCELED")
                        setResult(RESULT_CANCELED)
                        finish()
                        return@launch
                    }
                    var item: ProtonItem? = try {
                        withContext(Dispatchers.IO) { SealedVault.reveal(uuid!!) }
                    } catch (e: Exception) {
                        Log.w(TAG, "the unseal threw (${e.javaClass.simpleName}) — " +
                            "the gate retry")
                        null
                    }
                    if (item == null) {
                        // The window lag: ONE retry behind a fresh gate.
                        val again = ScreenlockGate.promptGate(
                            this@AutofillAuthActivity,
                            "Unlock the entry",
                            "One more device-lock press to open the entry")
                        if (again) {
                            item = try {
                                withContext(Dispatchers.IO) { SealedVault.reveal(uuid!!) }
                            } catch (e: Exception) {
                                Log.w(TAG, "the retry unseal threw (${e.javaClass.simpleName})")
                                null
                            }
                        }
                    }
                    if (item == null) {
                        Log.w(TAG, "the unseal failed for ${uuid?.take(8)} — RESULT_CANCELED")
                        Toast.makeText(this@AutofillAuthActivity,
                            "Couldn't open the entry — unlock the app once, then retry",
                            Toast.LENGTH_LONG).show()
                        setResult(RESULT_CANCELED)
                        finish()
                        return@launch
                    }
                    AutofillRevealStore.put(item, uuid)
                    Log.i(TAG, "revealed ${item.displayName} — RESULT_OK (the framework re-invokes)")
                    setResult(RESULT_OK)
                    finish()
                }
            }
        }
    }

    /** The screenlock signature flow (the copy of MainActivity's):
     *  KeystoreSigner.prepare → the BiometricPrompt bound to THIS exact
     *  Keystore op (the CryptoObject) → finish. Null = the declined/failed
     *  signature (the save rolls back — nothing saved). */
    private suspend fun screenLockSignFlow(bytes: ByteArray): ByteArray? =
        kotlinx.coroutines.suspendCancellableCoroutine { cont ->
            try {
                val signature = com.offlinepass.app.crypto.KeystoreSigner.prepare(bytes)
                val builder = android.hardware.biometrics.BiometricPrompt.Builder(this)
                    .setTitle("Sign vault change")
                    .setSubtitle("Screen-lock signature for this revision")
                if (android.os.Build.VERSION.SDK_INT >= 30) {
                    builder.setAllowedAuthenticators(
                        android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
                            or android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                } else {
                    builder.setDeviceCredentialAllowed(true)
                }
                val cancel = android.os.CancellationSignal()
                cont.invokeOnCancellation { cancel.cancel() }
                builder.build().authenticate(
                    android.hardware.biometrics.BiometricPrompt.CryptoObject(signature),
                    cancel,
                    androidx.core.content.ContextCompat.getMainExecutor(this),
                    object : android.hardware.biometrics.BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(
                            result: android.hardware.biometrics.BiometricPrompt.AuthenticationResult
                        ) {
                            cont.resume(
                                runCatching {
                                    com.offlinepass.app.crypto.KeystoreSigner.finish(signature)
                                }.getOrNull(), null)
                        }
                        override fun onAuthenticationError(code: Int, errString: CharSequence) {
                            Log.w(TAG, "screenlock signature declined: $code $errString")
                            cont.resume(null, null)
                        }
                    })
            } catch (e: Exception) {
                Log.w(TAG, "screenlock signature failed: ${e.message}")
                cont.resume(null, null)
            }
        }

    /** The prompt surfaces for the in-activity save: the touch reminder +
     *  the OpenPGP PIN — the SAME hooks MainActivity installs, pointed at
     *  this activity's dialogs (the interstitials the user referenced). */
    private fun installPromptSurfaces() {
        // THE SCREENLOCK COMMIT SIGNER: the save pipeline's screenlock
        // signing mode needs it — without the hook the save rolls back
        // ("Screenlock signer unavailable (UI layer absent)"). The same
        // flow as MainActivity's: prepare → the CryptoObject prompt →
        // finish. The save path's gate opens the 60s keystore window
        // right before addSealed, so this prompt stays silent within it
        // (ONE screenlock per save).
        VaultSession.keystoreSignerHook = { bytes ->
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                screenLockSignFlow(bytes)
            }
        }
        // The seal/unseal gate: the framework-enforced authenticator set
        // matching the seal key — the same wrapper MainActivity installs.
        VaultSession.sealGate = { title, subtitle ->
            ScreenlockGate.promptGate(this, title, subtitle, strongOrCredential = true)
        }
        VaultSession.openPgpPinPrompt = {
            kotlinx.coroutines.suspendCancellableCoroutine { cont ->
                runOnUiThread {
                    val input = EditText(this).apply {
                        inputType = android.text.InputType.TYPE_CLASS_NUMBER
                    }
                    AlertDialog.Builder(this)
                        .setTitle("OpenPGP PIN")
                        .setView(input)
                        .setPositiveButton("OK") { _, _ ->
                            cont.resume(input.text.toString().toCharArray(), null)
                        }
                        .setNegativeButton("Cancel") { _, _ -> cont.resume(null, null) }
                        .show()
                }
            }
        }
        // The touch reminder: poll the session's flag — the same dialog
        // MainActivity's router renders, here as a plain dialog.
        lifecycleScope.launch {
            while (true) {
                kotlinx.coroutines.delay(150)
                val wants = withContext(Dispatchers.Main) { VaultSession.touchPrompt }
                if (wants && touchDialog == null) {
                    touchDialog = AlertDialog.Builder(this@AutofillAuthActivity)
                        .setTitle("🔐 Touch your YubiKey")
                        .setMessage("The key is waiting — touch it (the LED blinks).")
                        .setCancelable(false)
                        .show()
                } else if (!wants && touchDialog != null) {
                    touchDialog?.dismiss()
                    touchDialog = null
                }
            }
        }
    }

    /**
     * THE SIMPLELOGIN API KEY for the alias chip, from EITHER vault
     * state: the unlocked session's item first; otherwise the sealed
     * cache — the uuid the sheet passed (or a manifest scan) → the
     * keystore-gated reveal. MUST run after the screenlock gate (the
     * keystore auth window). Throws when no reachable SL entry — the
     * caller degrades to the password-only fill.
     */
    private suspend fun resolveSimpleLoginApiKey(): String {
        VaultSession.simpleLoginItem()?.password?.takeIf { it.isNotBlank() }
            ?.let { return it }
        val uuid = intent.getStringExtra(EXTRA_SL_UUID)
            ?: SealedVault.manifestItems().firstOrNull { item ->
                item.urls.any { url ->
                    runCatching {
                        java.net.URI(url.trim()).host?.removePrefix("www.") == VaultSession.SL_HOST
                    }.getOrDefault(false)
                }
            }?.itemUuid
            ?: throw IllegalStateException("SimpleLogin not linked")
        return SealedVault.reveal(uuid)?.password?.takeIf { it.isNotBlank() }
            ?: throw IllegalStateException("the SimpleLogin key unsealed empty")
    }

    /**
     * THE INSERT for the autofill's save paths: the registry dedup first
     * (the platform's confirmed save and the card's Save can both arrive
     * for one generated password — only one insert), then addSealed, then
     * the registry mark + the silent trigger's cancellation.
     */
    private suspend fun insertAutofill(
        origin: String, username: String, password: String
    ): VaultSession.Result {
        // NO password-value dedup here: upsertSealed IS the dedup — the
        // site + identity match updates the same login in place (a
        // changed password, a re-save) and appends a new record only for
        // a genuinely different identity (if in doubt, one extra record).
        val item = ProtonItem(
            name = origin,
            username = username,
            urls = if (origin.contains('.') && !origin.contains(' '))
                listOf("https://$origin") else emptyList(),
            password = password)
        val r = try {
            VaultSession.upsertSealed(item.copy(modifyTime = 0))
        } catch (e: Exception) {
            VaultSession.Result.Error("${e.javaClass.simpleName}: ${e.message}")
        }
        if (r == VaultSession.Result.Success) {
            AutofillSaveOffer.cancelTrigger(this)
        }
        return r
    }

    companion object {
        private const val TAG = "OfflinepassAutofill"
        const val EXTRA_UUID = "uuid"
        const val EXTRA_NAME = "name"
        const val EXTRA_MODE = "mode"
        const val EXTRA_USERNAME = "username"
        const val EXTRA_PASSWORD = "password"
        const val EXTRA_CONFIRMED = "confirmed"
        const val EXTRA_SL_UUID = "sl_uuid"
        const val EXTRA_FILL_USERNAME_IDS = "fill_username_ids"
        const val EXTRA_FILL_PASSWORD_IDS = "fill_password_ids"

        /**
         * THE RESULT-CARRIED FILL: the filled dataset returned with the
         * auth result (EXTRA_AUTHENTICATION_RESULT) — the framework
         * applies it DIRECTLY in onAuthenticationResult. This bypasses
         * the re-invoke fallback whose session bookkeeping dies across
         * the save card (the browser's log: our result arrived as an
         * "empty intent" after onInvisibleForAutofill had EXPIRED the
         * response — the generated item came back as a re-offered chip,
         * never auto-filled). Mirrors datasetFor: the identity into the
         * username ids ONLY when non-blank (the no-clobber rule — the
         * ⚡ item has none), the password always. Null = the caller
         * degrades to the bare RESULT_OK (the re-invoke path).
         */
        internal fun buildResultResponse(
            context: Context, intent: Intent, label: String, item: ProtonItem
        ): FillResponse? {
            val usernameIds =
                intent.getParcelableArrayListExtra<AutofillId>(EXTRA_FILL_USERNAME_IDS)
            val passwordIds =
                intent.getParcelableArrayListExtra<AutofillId>(EXTRA_FILL_PASSWORD_IDS)
            if (passwordIds.isNullOrEmpty()) {
                Log.i(TAG, "the result fill skipped — no password ids in the auth intent")
                return null
            }
            val view = RemoteViews(context.packageName, R.layout.autofill_item).apply {
                setTextViewText(R.id.autofill_text, label)
            }
            val ds = Dataset.Builder()
            if (item.identity.isNotBlank()) {
                usernameIds.orEmpty().forEach { id ->
                    ds.setValue(id, AutofillValue.forText(item.identity), view)
                }
            }
            passwordIds.forEach { id ->
                ds.setValue(id, AutofillValue.forText(item.password), view)
            }
            return FillResponse.Builder().addDataset(ds.build()).build()
        }
        const val MODE_REVEAL = "reveal"
        const val MODE_GENERATE = "generate"
        const val MODE_GENERATE_ALIAS = "generate_alias"
        const val MODE_SAVE = "save"
    }
}
