package com.linuxpass.app.ui

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
    data class Qr(val itemUuid: String) : Screen()
    data class Qrft(val itemUuid: String) : Screen()
    object Setup : Screen()
}

/**
 * First run: create a new vault (GitHub-managed or local-only) or load an
 * existing one (GitHub + PAT / USB file). Mirrors user_flows.md "Initial
 * setup".
 */
@Composable
fun SetupChoiceScreen(
    defaults: Pair<String, String>, // remote, recipient emails
    onConfigured: (remote: String?, emails: List<String>) -> Unit,
    status: String,
    onLoadUsb: () -> Unit
) {
    var remote by remember { mutableStateOf(defaults.first) }
    var email by remember { mutableStateOf(defaults.second) }
    var mode by remember { mutableStateOf("load") }
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("linuxpass", style = MaterialTheme.typography.headlineSmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = mode == "load", onClick = { mode = "load" }, label = { Text("Load existing") })
            FilterChip(selected = mode == "new", onClick = { mode = "new" }, label = { Text("New vault") })
        }
        OutlinedTextField(
            value = remote, onValueChange = { remote = it },
            label = { Text("GitHub HTTPS remote") }, singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = email, onValueChange = { email = it },
            label = { Text("OpenKeyChain recipient email(s), comma-separated") }, singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        Text(
            "USB load: no remote configured — local-only mode (the imported file becomes the vault).",
            style = MaterialTheme.typography.bodySmall
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = {
                val r = remote.trim().ifBlank { null }
                val emails = email.split(",").map { it.trim() }.filter { it.isNotBlank() }
                onConfigured(r, emails)
            }) { Text(if (mode == "new") "Create (empty vault)" else "Load from GitHub") }
            OutlinedButton(onClick = { onLoadUsb() }) { Text("Load from USB file") }
        }
        if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodyMedium)
    }
}

/** Locked state: one button, one key touch. */
@Composable
fun UnlockScreen(status: String, busy: String?, onUnlock: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(64.dp))
        Text("Vault locked", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Unlocking requires your hardware key (touch + PIN via OpenKeyChain).",
            style = MaterialTheme.typography.bodyMedium
        )
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
                    modifier = Modifier.fillMaxWidth(),
                    trailingContent = { Text(if (item.totpUri.isNotBlank()) "⏱" else "") }
                )
                HorizontalDivider()
            }
        }
        Button(onClick = onAdd, modifier = Modifier.fillMaxWidth()) { Text("Add entry") }
    }
}
