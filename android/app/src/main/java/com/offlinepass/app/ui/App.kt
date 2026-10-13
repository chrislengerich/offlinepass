package com.offlinepass.app.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.offlinepass.app.vault.ProtonItem
import com.offlinepass.app.vault.VaultSession

/** App navigation state. */
sealed class Screen {
    object SetupChoice : Screen()
    object Search : Screen()
    data class Detail(val itemUuid: String) : Screen()
    object AddEntry : Screen()
    data class Qrft(val itemUuid: String) : Screen()
    /** Multi-entry QRFT export, payload already built (Settings flow). */
    data class QrftPayload(val payload: String) : Screen()
    /** Entry picker for the multi-entry QRFT export. */
    object ExportPick : Screen()
    /** Camera scanner for the import-from-QRFT flow. */
    object QrftScan : Screen()
    object Setup : Screen()
}

/**
 * First run (user_flows.md "Initial setup"): create a NEW vault (empty, or
 * imported from a plaintext Proton Pass export — recipients picked from
 * OpenKeyChain afterwards) or LOAD an existing vault (GitHub + PAT / USB).
 */
@Composable
fun SetupChoiceScreen(
    defaultRemote: String,
    defaultEmails: String,
    prefillPat: String,
    status: String,
    recipientIds: List<Long>,
    onPickRecipients: () -> Unit,
    onRemoveRecipient: (Long) -> Unit,
    onNewVault: (remote: String?, pat: String) -> Unit,
    onImportProton: (remote: String?, pat: String, uri: android.net.Uri) -> Unit,
    onLoadGitHub: (remote: String, emails: List<String>, pat: String) -> Unit,
    onLoadUsb: () -> Unit
) {
    var remote by remember { mutableStateOf(defaultRemote) }
    var email by remember { mutableStateOf(defaultEmails) }
    var pat by remember { mutableStateOf(prefillPat) }
    var mode by remember { mutableStateOf("load") }

    val importPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let { onImportProton(remote.trim().ifBlank { null }, pat.trim(), it) } }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("offlinepass", style = MaterialTheme.typography.headlineSmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = mode == "load", onClick = { mode = "load" }, label = { Text("Load existing") })
            FilterChip(selected = mode == "new", onClick = { mode = "new" }, label = { Text("New vault") })
        }

        if (mode == "new") {
            Text("New vault — recipients are picked from OpenKeyChain before creating/importing.",
                style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(
                value = remote, onValueChange = { remote = it },
                label = { Text("GitHub HTTPS remote (blank = local-only)") }, singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            if (remote.isNotBlank()) {
                OutlinedTextField(
                    value = pat, onValueChange = { pat = it },
                    label = { Text("Fine-grained PAT (stored encrypted)") },
                    singleLine = true,
                    visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
            }
            // Recipients — same UI as the Setup tab, BEFORE create/import.
            Text("Recipients (from OpenKeyChain picker)", style = MaterialTheme.typography.titleSmall)
            if (recipientIds.isEmpty()) {
                Text("(none — pick at least one before creating/importing)",
                    style = MaterialTheme.typography.bodySmall)
            }
            recipientIds.forEach { id ->
                Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Text("0x%016X".format(id), modifier = Modifier.weight(1f))
                    TextButton(onClick = { onRemoveRecipient(id) }) { Text("Remove") }
                }
            }
            Button(onClick = onPickRecipients, enabled = true, modifier = Modifier.fillMaxWidth()) {
                Text("Add recipient (pick in OpenKeyChain)")
            }
            Button(
                onClick = { onNewVault(remote.trim().ifBlank { null }, pat.trim()) },
                enabled = recipientIds.isNotEmpty(),
                modifier = Modifier.fillMaxWidth()
            ) { Text("Create empty vault") }
            Button(
                onClick = { importPicker.launch(arrayOf("*/*")) },
                enabled = recipientIds.isNotEmpty(),
                modifier = Modifier.fillMaxWidth()
            ) { Text("Import from Proton Pass export") }
            if (remote.isBlank()) Text(
                "Local-only mode: the import is encrypted to the recipients and kept on this device.",
                style = MaterialTheme.typography.bodySmall
            )
        } else {
            OutlinedTextField(
                value = remote, onValueChange = { remote = it },
                label = { Text("GitHub HTTPS remote") }, singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = email, onValueChange = { email = it },
                label = { Text("OpenKeyChain recipient email(s)") }, singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = pat, onValueChange = { pat = it },
                label = { Text("Fine-grained PAT (stored encrypted)") },
                singleLine = true,
                visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    val emails = email.split(",").map { it.trim() }.filter { it.isNotBlank() }
                    onLoadGitHub(remote.trim(), emails, pat.trim())
                }) { Text("Load from GitHub") }
                OutlinedButton(onClick = { onLoadUsb() }) { Text("Load from USB file") }
            }
        }
        if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodyMedium)
    }
}

/** Locked state: one button, one key touch — plus a PAT field when the
 * remote needs a token that isn't stored yet. */
@Composable
fun UnlockScreen(
    status: String,
    busy: String?,
    patMissing: Boolean,
    onPatSave: (String) -> Unit,
    onUnlock: () -> Unit
) {
    var patInput by remember { mutableStateOf("") }
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(48.dp))
        Text("Vault locked", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Unlocking requires your hardware key (touch + PIN via OpenKeyChain).",
            style = MaterialTheme.typography.bodyMedium
        )
        if (patMissing) {
            OutlinedTextField(
                value = patInput, onValueChange = { patInput = it },
                label = { Text("Fine-grained PAT (not stored yet)") },
                singleLine = true,
                visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )
            Button(onClick = { if (patInput.isNotBlank()) onPatSave(patInput.trim()); patInput = "" },
                enabled = patInput.isNotBlank()) {
                Text("Save PAT (encrypted)")
            }
        }
        Button(onClick = onUnlock, enabled = busy == null) {
            Text(busy ?: "Unlock")
        }
        if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodyMedium)
    }
}

/** Entry matching, ported from passlib: all words must match somewhere. */
fun ProtonItem.matches(query: String): Boolean {
    if (query.isBlank()) return true
    val haystack = listOf(name, username, email, urls.joinToString(" "), note)
        .joinToString(" ").lowercase()
    return query.lowercase().split(" ").filter { it.isNotBlank() }.all { it in haystack }
}

/** Main page: type-to-filter search over plaintext-matched rows (TUI parity).
 *  Shows the entry count, per-entry last-modified dates, and a toggleable
 *  secondary sort (within equal names, most recently modified first). */
@Composable
fun SearchScreen(
    items: List<ProtonItem>,
    busy: String?,
    query: String,
    onQueryChange: (String) -> Unit,
    onOpen: (ProtonItem) -> Unit,
    onAdd: () -> Unit,
    onSetup: () -> Unit
) {
    var sortByModified by remember { mutableStateOf(VaultSession.sortByModifiedPref()) }
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("offlinepass", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            TextButton(onClick = onSetup) { Text("Setup") }
        }
        OutlinedTextField(
            value = query, onValueChange = onQueryChange,
            label = { Text("Search (site / user / email)") },
            singleLine = true, modifier = Modifier.fillMaxWidth()
        )
        val filtered = items.filter { it.matches(query) }
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                if (query.isBlank()) "${items.size} entries" else "${filtered.size} of ${items.size} entries",
                style = MaterialTheme.typography.bodySmall
            )
            Spacer(Modifier.weight(1f))
            FilterChip(
                selected = sortByModified,
                onClick = {
                    sortByModified = !sortByModified
                    VaultSession.setSortByModifiedPref(sortByModified)
                },
                label = { Text(if (sortByModified) "Modified ↓" else "Name only") }
            )
        }
        if (busy != null) LinearProgressIndicator(modifier = Modifier.fillMaxWidth().padding(top = 8.dp))
        val sorted = if (sortByModified)
            filtered.sortedWith(compareBy({ it.displayName.lowercase() }, { -it.modifyTime }))
        else filtered.sortedBy { it.displayName.lowercase() }
        LazyColumn(modifier = Modifier.weight(1f).padding(top = 4.dp)) {
            items(sorted, key = { it.itemUuid }) { item ->
                ListItem(
                    headlineContent = { Text(item.displayName) },
                    supportingContent = {
                        Column {
                            Text(item.identity.ifBlank { "(no identity)" })
                            if (item.modifyTime > 0)
                                Text("Modified ${item.modifyTimeText}", style = MaterialTheme.typography.bodySmall)
                        }
                    },
                    modifier = Modifier.fillMaxWidth().clickable { onOpen(item) },
                    trailingContent = { Text(if (item.totpUri.isNotBlank()) "⏱" else "") }
                )
                HorizontalDivider()
            }
        }
        Button(onClick = onAdd, modifier = Modifier.fillMaxWidth()) { Text("Add entry") }
    }
}
