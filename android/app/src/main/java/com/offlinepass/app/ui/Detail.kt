package com.offlinepass.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import kotlinx.coroutines.launch
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.offlinepass.app.simplelogin.SimpleLoginHttp
import com.offlinepass.app.vault.ProtonItem
import com.offlinepass.app.vault.VaultSession
import com.offlinepass.app.vault.Totp
import org.json.JSONObject

/** Compact Proton-JSON payload for one entry — the QRFT export format. */
fun entryPayload(item: ProtonItem): String = item.toProtonJson().toString()

/** THE FIELD COPY: the value → the clipboard, flagged SENSITIVE (API 33+
 *  hides it from the system clipboard-preview overlay — an onlooker-safe
 *  copy), with the toast confirmation. The blank fields disable their
 *  copy buttons — an empty clip helps no one. TextButtons, not icons:
 *  the app's UI language (and no icons dependency). */
fun copyFieldToClipboard(context: android.content.Context, label: String, value: String) {
    val cm = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE)
        as? android.content.ClipboardManager ?: return
    val clip = android.content.ClipData.newPlainText("offlinepass $label", value)
    if (android.os.Build.VERSION.SDK_INT >= 33) {
        clip.description.extras = android.os.PersistableBundle().apply {
            putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
    }
    cm.setPrimaryClip(clip)
    android.widget.Toast.makeText(context, "$label copied",
        android.widget.Toast.LENGTH_SHORT).show()
}

/** THE COPY GLYPH: the two-sheet copy icon drawn directly — the material
 *  icon lives in material-icons-extended (a multi-MB artifact for one
 *  glyph; the low-dependency supply chain says draw it). Two stroked
 *  rounded rects, tight overlap; the front sheet's SURFACE fill knocks
 *  the back sheet's stroke out of the overlap (the classic clean look). */
@Composable
fun CopyGlyph(
    modifier: Modifier = Modifier,
    tint: androidx.compose.ui.graphics.Color = MaterialTheme.colorScheme.onSurfaceVariant
) {
    val sheet = MaterialTheme.colorScheme.surface
    androidx.compose.foundation.Canvas(modifier.size(16.dp)) {
        val stroke = androidx.compose.ui.graphics.drawscope.Stroke(1.6.dp.toPx())
        val r = androidx.compose.ui.geometry.CornerRadius(1.2.dp.toPx())
        // THE BACK SHEET (up-right).
        drawRoundRect(tint,
            topLeft = androidx.compose.ui.geometry.Offset(size.width * 0.26f, 0f),
            size = androidx.compose.ui.geometry.Size(size.width * 0.74f, size.height * 0.74f),
            cornerRadius = r, style = stroke)
        // THE FRONT SHEET (down-left): the surface fill erases the back
        // sheet's crossing lines inside it, then the outline redraws.
        drawRoundRect(sheet,
            topLeft = androidx.compose.ui.geometry.Offset(0f, size.height * 0.26f),
            size = androidx.compose.ui.geometry.Size(size.width * 0.74f, size.height * 0.74f),
            cornerRadius = r)
        drawRoundRect(tint,
            topLeft = androidx.compose.ui.geometry.Offset(0f, size.height * 0.26f),
            size = androidx.compose.ui.geometry.Size(size.width * 0.74f, size.height * 0.74f),
            cornerRadius = r, style = stroke)
    }
}

/** The copy ICON button for one field (the icon form of CopyFieldButton). */
@Composable
fun CopyIconButton(value: () -> String, label: String) {
    val context = androidx.compose.ui.platform.LocalContext.current
    IconButton(
        onClick = { copyFieldToClipboard(context, label, value()) },
        enabled = value().isNotBlank(),
        modifier = Modifier.size(28.dp)
    ) { CopyGlyph() }
}

/**
 * Entry detail: editable fields (username, email, URLs, password), live TOTP,
 * Save changes, Regenerate password (confirm), Export as QRFT, enroll TOTP,
 * delete.
 */
@Composable
fun EntryDetailScreen(
    item: ProtonItem,
    status: String,
    busy: String?,
    onBack: () -> Unit,
    onExportQr: (Boolean) -> Unit,
    pairedDevices: List<com.offlinepass.app.vault.DeviceRecord> = emptyList(),
    onSaveChanges: (ProtonItem) -> Unit,
    onEnrollTotp: (uri: String, onDone: (Boolean) -> Unit) -> Unit,
    onDelete: () -> Unit,
    /** The raw-QR scan's pending otpauth:// URI (the scan never saves
     *  alone — it pre-fills the entry for review). */
    pendingTotpUri: String = "",
    onTotpUriConsumed: () -> Unit = {},
    onScanTotp: () -> Unit = {},
) {
    // Editable copies — applied to the item only on Save.
    var username by remember(item.itemUuid) { mutableStateOf(item.username) }
    var email by remember(item.itemUuid) { mutableStateOf(item.email) }
    var urls by remember(item.itemUuid) { mutableStateOf(item.urls.joinToString(", ")) }
    var password by remember(item.itemUuid) { mutableStateOf(item.password) }
    var note by remember(item.itemUuid) { mutableStateOf(item.note) }
    var showPassword by remember { mutableStateOf(false) }

    val dirty = username != item.username || email != item.email ||
        urls != item.urls.joinToString(", ") || password != item.password ||
        note != item.note

    var showRegenConfirm by remember { mutableStateOf(false) }
    var revealed by remember { mutableStateOf(false) }
    var totp by remember { mutableStateOf<Pair<String, Int>?>(null) }
    var showTotpEntry by remember { mutableStateOf(false) }
    var showReenrollConfirm by remember { mutableStateOf(false) }
    // THE COUNTER'S SECRET SOURCE: the pane's own state — the enrollment
    // Save updates it FIRST, so the counter re-renders with the new
    // secret immediately (the item param's in-place updates may never
    // reach the recomposition).
    var activeTotpUri by remember(item.itemUuid) { mutableStateOf(item.totpUri) }
    // THE SCANNED URI: the raw-QR scan lands here and re-opens the entry —
    // the row consumes the URI into its own input (the scan never saves
    // alone; the user reviews before saving).
    LaunchedEffect(pendingTotpUri) {
        if (pendingTotpUri.isNotBlank()) showTotpEntry = true
    }

    // -- THE SIMPLELOGIN ALIAS TOGGLE (the item-page management) ------------
    // The gate: the SL api-key item exists AND the email = an SL alias on
    // our domain. The items carry NO SL state and make NO network requests
    // by default: the status check = one list call; the toggle = one
    // call. The state lives in the screen only.
    val slLinked = VaultSession.simpleLoginItem() != null
    val slCandidate = slLinked && VaultSession.isSimpleLoginAlias(email)
    var slStatus by remember(item.itemUuid) { mutableStateOf<String?>(null) }
    var slAliasEnabled by remember(item.itemUuid) { mutableStateOf<Boolean?>(null) }
    var slBusy by remember(item.itemUuid) { mutableStateOf(false) }
    var slAliasId by remember(item.itemUuid) { mutableStateOf<Long?>(null) }
    val slScope = androidx.compose.runtime.rememberCoroutineScope()

    if (activeTotpUri.isNotBlank()) {
        LaunchedEffect(activeTotpUri) {
            while (true) {
                totp = runCatching { Totp.generate(activeTotpUri) }.getOrNull()
                kotlinx.coroutines.delay(1000)
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(androidx.compose.foundation.rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("← Back") }
            Text(item.displayName, style = MaterialTheme.typography.titleLarge)
        }
        OutlinedTextField(
            value = urls, onValueChange = { urls = it },
            label = { Text("URLs (comma-separated)") },
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = username, onValueChange = { username = it },
            label = { Text("Username") }, singleLine = true,
            trailingIcon = {
                // NO DATA = NO BUTTON (the disabled ghost just cluttered
                // the field).
                if (username.isNotBlank()) CopyIconButton({ username }, "Username")
            },
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = email, onValueChange = { email = it },
            label = { Text("Email") }, singleLine = true,
            trailingIcon = {
                if (email.isNotBlank()) CopyIconButton({ email }, "Email")
            },
            modifier = Modifier.fillMaxWidth()
        )
        if (slCandidate) {
            // THE SL ALIAS MANAGEMENT: the status check (one list call)
            // reveals the enabled state and arms the toggle (one call).
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = {
                    val apiKey = VaultSession.simpleLoginItem()?.password ?: return@TextButton
                    slBusy = true; slStatus = null
                    slScope.launch {
                        slStatus = try {
                            val found = SimpleLoginHttp().listAliases(
                                apiKey, query = email.trim())
                                .firstOrNull { it.email.equals(email.trim(), true) }
                            if (found == null) {
                                slAliasId = null; slAliasEnabled = null
                                "No SimpleLogin alias matches this email."
                            } else {
                                slAliasId = found.id; slAliasEnabled = found.enabled
                                "SimpleLogin: ${found.email} is " +
                                    if (found.enabled) "ENABLED" else "DISABLED"
                            }
                        } catch (e: Exception) {
                            "SimpleLogin error: ${e.message}"
                        }; slBusy = false
                    }
                }, enabled = !slBusy) { Text(if (slBusy) "Checking…" else "Check SimpleLogin status") }
                if (slAliasId != null && slAliasEnabled != null && !slBusy) {
                    Button(onClick = {
                        val apiKey = VaultSession.simpleLoginItem()?.password ?: return@Button
                        val id = slAliasId ?: return@Button
                        slBusy = true
                        slScope.launch {
                            slStatus = try {
                                slAliasEnabled = SimpleLoginHttp().toggleAlias(apiKey, id)
                                "SimpleLogin: ${email.trim()} is now " +
                                    if (slAliasEnabled == true) "ENABLED" else "DISABLED"
                            } catch (e: Exception) {
                                "SimpleLogin error: ${e.message}"
                            }; slBusy = false
                        }
                    }, enabled = !slBusy) {
                        Text(if (slAliasEnabled == true) "Disable alias" else "Enable alias")
                    }
                }
            }
            if (slStatus != null) Text(slStatus!!, style = MaterialTheme.typography.bodySmall)
        }
        OutlinedTextField(
            value = password, onValueChange = { password = it },
            label = { Text("Password") }, singleLine = true,
            visualTransformation = if (showPassword) VisualTransformation.None
                                   else PasswordVisualTransformation(),
            trailingIcon = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (password.isNotBlank()) CopyIconButton({ password }, "Password")
                    TextButton(onClick = { showPassword = !showPassword }) {
                        Text(if (showPassword) "Hide" else "Show")
                    }
                }
            },
            modifier = Modifier.fillMaxWidth()
        )
        // Regenerate: a small inline action right under the password —
        // not a full-width button competing with the page actions.
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = androidx.compose.foundation.layout.Arrangement.End
        ) {
            TextButton(onClick = { showRegenConfirm = true }, enabled = busy == null) {
                Text("Regenerate password", style = MaterialTheme.typography.bodySmall)
            }
        }
        if (activeTotpUri.isBlank()) {
            TextButton(onClick = { showTotpEntry = true }, enabled = busy == null) {
                Text("Enroll TOTP", style = MaterialTheme.typography.bodySmall)
            }
        } else {
            if (totp != null) {
                val (code, remaining) = totp!!
                // THE CURRENT CODE, COPYABLE: the 6-digit value on the
                // clipboard — the paste into the site's 2FA field without
                // retyping. Copies the LIVE value (the remaining-seconds
                // text stays display-only).
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("TOTP: $code  (${remaining}s)",
                        style = MaterialTheme.typography.titleMedium)
                    CopyIconButton({ code }, "TOTP")
                }
            }
            // Re-enroll: the same small inline action as Regenerate —
            // right-justified under the TOTP display.
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = androidx.compose.foundation.layout.Arrangement.End
            ) {
                TextButton(onClick = { showReenrollConfirm = true }, enabled = busy == null) {
                    Text("Re-enroll TOTP", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        if (showTotpEntry) {
            TotpEnrollRow(
                pendingTotpUri = pendingTotpUri,
                onTotpUriConsumed = onTotpUriConsumed,
                onScan = onScanTotp,
                busy = busy,
                onEnroll = { newUri ->
                    // THE COUNTER AFTER THE SUCCESSFUL SAVE: the pane's
                    // secret source updates only when the save confirms —
                    // a failed/declined save leaves the old secret ticking.
                    onEnrollTotp(newUri) { success ->
                        if (success) activeTotpUri = newUri
                    }
                },
                onDismiss = { showTotpEntry = false }
            )
        }
        OutlinedTextField(
            value = note, onValueChange = { note = it },
            label = { Text("Notes") },
            minLines = 4, maxLines = 8,
            modifier = Modifier.fillMaxWidth()
        )
        // THE KEYBOARD GOES WITH THE SAVE: the entry is committed — an
        // open keyboard over a committed entry is noise. (The controller
        // is read at composition; hiding happens in the click.)
        val keyboard = androidx.compose.ui.platform.LocalSoftwareKeyboardController.current
        Button(
            onClick = {
                keyboard?.hide()
                onSaveChanges(item.copy(
                    username = username.trim(),
                    email = email.trim(),
                    password = password,
                    urls = urls.split(",").map { it.trim() }.filter { it.isNotBlank() },
                    note = note
                ))
            },
            enabled = dirty && busy == null,
            modifier = Modifier.fillMaxWidth()
        ) { Text("Save changes") }
        // Save status sits directly under the button.
        if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodyMedium)
        if (dirty) Text("Unsaved changes — Save to persist.", style = MaterialTheme.typography.bodySmall)

        // THE RE-ENROLL WARNING: overwriting an enrolled TOTP needs the
        // explicit yes — the yes opens the enrollment row; the save inside
        // it commits the replacement.
        if (showReenrollConfirm) {
            androidx.compose.material3.AlertDialog(
                onDismissRequest = { showReenrollConfirm = false },
                title = { Text("Re-enroll TOTP?") },
                text = { Text("The current TOTP will be replaced.") },
                confirmButton = {
                    TextButton(onClick = {
                        showReenrollConfirm = false
                        showTotpEntry = true
                    }) { Text("Yes") }
                },
                dismissButton = {
                    TextButton(onClick = { showReenrollConfirm = false }) { Text("No") }
                }
            )
        }

        if (item.modifyTime > 0) {
            Text("Last modified: ${item.modifyTimeText}", style = MaterialTheme.typography.bodySmall)
        }

        var exportEncrypted = remember { mutableStateOf(true) }
        Button(onClick = { onExportQr(exportEncrypted.value) }, modifier = Modifier.fillMaxWidth()) {
            Text("Export as QRFT")
        }
        if (pairedDevices.isNotEmpty()) {
            // Plan 2: single-entry export defaults to the device-wrapped
            // paste (all paired keys — any one opens it). Unchecked = the
            // plain QRFT anyone can read.
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { exportEncrypted.value = !exportEncrypted.value },
                verticalAlignment = Alignment.CenterVertically
            ) {
                Checkbox(checked = exportEncrypted.value, onCheckedChange = { exportEncrypted.value = it })
                Text(
                    "Encrypt to paired paste keys (${pairedDevices.size})",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        } else {
            Text(
                "No paste devices paired (Setup → Pair paste device) — the QR will be plain.",
                style = MaterialTheme.typography.bodySmall
            )
        }
        var showDeleteConfirm by remember { mutableStateOf(false) }
        Button(onClick = { showDeleteConfirm = true }, modifier = Modifier.fillMaxWidth()) {
            Text("Delete entry")
        }
        if (showDeleteConfirm) {
            AlertDialog(
                onDismissRequest = { showDeleteConfirm = false },
                title = { Text("Delete \"${item.displayName}\"?") },
                confirmButton = {
                    TextButton(onClick = { showDeleteConfirm = false; onDelete() }) {
                        Text("Delete") }
                },
                dismissButton = {
                    TextButton(onClick = { showDeleteConfirm = false }) { Text("Cancel") }
                }
            )
        }
        if (busy != null) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())

        if (showRegenConfirm) {
            AlertDialog(
                onDismissRequest = { showRegenConfirm = false },
                title = { Text("Regenerate password?") },
                text = { Text("The current password is replaced by a generated one. "
                    + "Save the entry to persist it.") },
                confirmButton = {
                    TextButton(onClick = {
                        showRegenConfirm = false
                        password = com.offlinepass.app.vault.PasswordGen.password()
                        // Not saved yet — the user persists via Save changes.
                    }) { Text("Regenerate") }
                },
                dismissButton = {
                    TextButton(onClick = { showRegenConfirm = false }) { Text("Cancel") }
                }
            )
        }
    }
}

/**
 * THE TOTP ENROLLMENT ROW: the inline entry (next to the Enroll TOTP
 * button), the camera scan (the scanned URI pre-fills the entry — the
 * scan never saves alone), and the explicit save. The row is shared by
 * every detail pane (the sealed reveal, the revealed, the unlocked).
 */
@Composable
fun TotpEnrollRow(
    pendingTotpUri: String,
    onTotpUriConsumed: () -> Unit,
    onScan: () -> Unit,
    busy: String?,
    onEnroll: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var totpInput by remember { mutableStateOf("") }
    LaunchedEffect(pendingTotpUri) {
        if (pendingTotpUri.isNotBlank()) {
            totpInput = pendingTotpUri
            onTotpUriConsumed()
        }
    }
    OutlinedTextField(
        value = totpInput,
        onValueChange = { totpInput = it },
        label = { Text("Base32 secret or otpauth:// URI") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth()
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
            onClick = {
                onEnroll(Totp.normalizeSecretInput(totpInput))
                onDismiss()
            },
            enabled = totpInput.isNotBlank() && busy == null
        ) { Text("Save") }
        OutlinedButton(onClick = onScan) { Text("Scan QR") }
        OutlinedButton(onClick = onDismiss) { Text("Cancel") }
    }
}
