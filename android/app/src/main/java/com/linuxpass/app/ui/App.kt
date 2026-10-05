package com.linuxpass.app.ui

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
import com.linuxpass.app.vault.ProtonItem
import com.linuxpass.app.vault.VaultSession

/** App navigation state. */
sealed class Screen {
    object SetupChoice : Screen()
    object Search : Screen()
    data class Detail(val itemUuid: String) : Screen()
    object AddEntry : Screen()
    data class Qrft(val itemUuid: String) : Screen()
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
    onNewVault: (remote: String?) -> Unit,
    onImportProton: (remote: String?, uri: android.net.Uri) -> Unit,
    onLoadGitHub: (remote: String, emails: List<String>, pat: String) -> Unit,
    onLoadUsb: () -> Unit
) {
    var remote by remember { mutableStateOf(defaultRemote) }
    var email by remember { mutableStateOf(defaultEmails) }
    var pat by remember { mutableStateOf(prefillPat) }
    var mode by remember { mutableStateOf("load") }

    val importPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let { onImportProton(remote.trim().ifBlank { null }, it) } }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("linuxpass", style = MaterialTheme.typography.headlineSmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = mode == "load", onClick = { mode = "load" }, label = { Text("Load existing") })
            FilterChip(selected = mode == "new", onClick = { mode = "new" }, label = { Text("New vault") })
        }

        if (mode == "new") {
            Text("New vault — pick recipients from OpenKeyChain after creating.",
                style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(
                value = remote, onValueChange = { remote = it },
                label = { Text("GitHub HTTPS remote (blank = local-only)") }, singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Button(onClick = { onNewVault(remote.trim().ifBlank { null }) }, modifier = Modifier.fillMaxWidth()) {
                Text("Create empty vault")
            }
            Button(
                onClick = { importPicker.launch(arrayOf("*/*")) },
                enabled = remote.isNotBlank(),
                modifier = Modifier.fillMaxWidth()
            ) { Text("Import from Proton Pass export") }
            if (remote.isBlank()) Text(
                "Import needs a remote (the import is encrypted to recipients on save).",
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

/** Main page: type-to-filter search over plaintext-matched rows (TUI parity). */
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
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("linuxpass", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            TextButton(onClick = onSetup) { Text("Setup") }
        }
        OutlinedTextField(
            value = query, onValueChange = onQueryChange,
            label = { Text("Search (site / user / email)") },
            singleLine = true, modifier = Modifier.fillMaxWidth()
        )
        if (busy != null) LinearProgressIndicator(modifier = Modifier.fillMaxWidth().padding(top = 8.dp))
        val filtered = items.filter { it.matches(query) }
        LazyColumn(modifier = Modifier.weight(1f).padding(top = 8.dp)) {
            items(filtered, key = { it.itemUuid }) { item ->
                ListItem(
                    headlineContent = { Text(item.displayName) },
                    supportingContent = { Text(item.identity.ifBlank { "(no identity)" }) },
                    modifier = Modifier.fillMaxWidth().clickable { onOpen(item) },
                    trailingContent = { Text(if (item.totpUri.isNotBlank()) "⏱" else "") }
                )
                HorizontalDivider()
            }
        }
        Button(onClick = onAdd, modifier = Modifier.fillMaxWidth()) { Text("Add entry") }
    }
}
