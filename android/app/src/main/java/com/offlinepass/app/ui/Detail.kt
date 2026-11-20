package com.offlinepass.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.offlinepass.app.vault.ProtonItem
import com.offlinepass.app.vault.Totp
import org.json.JSONObject

/** Compact Proton-JSON payload for one entry — the QRFT export format. */
fun entryPayload(item: ProtonItem): String = item.toProtonJson().toString()

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
    onEnrollTotp: (String) -> Unit,
    onDelete: () -> Unit
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
    var totpInput by remember { mutableStateOf("") }

    if (item.totpUri.isNotBlank()) {
        LaunchedEffect(item.totpUri) {
            while (true) {
                totp = runCatching { Totp.generate(item.totpUri) }.getOrNull()
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
            value = username, onValueChange = { username = it },
            label = { Text("Username") }, singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = email, onValueChange = { email = it },
            label = { Text("Email") }, singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = urls, onValueChange = { urls = it },
            label = { Text("URLs (comma-separated)") },
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = password, onValueChange = { password = it },
            label = { Text("Password") }, singleLine = true,
            visualTransformation = if (showPassword) VisualTransformation.None
                                   else PasswordVisualTransformation(),
            trailingIcon = {
                TextButton(onClick = { showPassword = !showPassword }) {
                    Text(if (showPassword) "Hide" else "Show")
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
        if (item.totpUri.isBlank()) {
            Button(onClick = { showTotpEntry = true }, enabled = busy == null,
                modifier = Modifier.fillMaxWidth()) {
                Text("Enroll TOTP")
            }
        } else {
            Text("TOTP enrolled", style = MaterialTheme.typography.bodySmall)
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

        if (totp != null) {
            val (code, remaining) = totp!!
            Text("TOTP: $code  (${remaining}s)", style = MaterialTheme.typography.titleMedium)
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
        Button(onClick = onDelete, modifier = Modifier.fillMaxWidth()) {
            Text("Delete entry")
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
        if (showTotpEntry) {
            OutlinedTextField(
                value = totpInput,
                onValueChange = { totpInput = it },
                label = { Text("Base32 secret or otpauth:// URI") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    onEnrollTotp(Totp.normalizeSecretInput(totpInput))
                    showTotpEntry = false
                }) { Text("Save") }
                OutlinedButton(onClick = { showTotpEntry = false }) { Text("Cancel") }
            }
        }
    }
}
