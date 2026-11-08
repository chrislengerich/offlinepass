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
    /** Device chooser for the export: wrap to a paired extension key or plain. */
    data class ExportTarget(val items: List<ProtonItem>) : Screen()
    /** Camera scanner for the import-from-QRFT flow. */
    object QrftScan : Screen()
    /** Single-QR scanner for pairing a paste device (extension). */
    object PairScan : Screen()
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
    onNewVault: () -> Unit,
    onImportProton: (remote: String?, pat: String, uri: android.net.Uri) -> Unit,
    onLoadGitHub: (remote: String, emails: List<String>, pat: String) -> Unit,
    onLoadUsb: () -> Unit,
    onShowSshKey: () -> Unit = {},
    onEnrollYubikeySsh: (sshLine: String, subkeyId: String) -> Unit = { _, _ -> }
) {
    var remote by remember {
        // Prepopulate the URL per the DEFAULT sync-auth choice: an https
        // default viewed as an SSH choice becomes the git@ form.
        val initial = if (VaultSession.sshSyncMode() != "pat" &&
            defaultRemote.startsWith("https://")
        ) defaultRemote.replaceFirst("https://", "git@").replaceFirst("/", ":")
        else defaultRemote
        mutableStateOf(initial)
    }
    var pat by remember { mutableStateOf(prefillPat) }
    var mode by remember { mutableStateOf("load") }
    // The load flow's sync-auth choice: screenlock SSH (default) / YubiKey
    // SSH / PAT (HTTPS, deprecated). The URL's scheme prefix follows the
    // choice (same interaction as Setup's Connect-remote dialog).
    var loadAuth by remember { mutableStateOf(VaultSession.sshSyncMode()) }
    var sshLine by remember { mutableStateOf(VaultSession.yubikeySshLine() ?: "") }
    var subkeyId by remember { mutableStateOf(VaultSession.yubikeyAuthSubkeyId()?.toString() ?: "") }

    val importPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let { onImportProton(null, "", it) } }

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
            Text("New vault — local-only: everything is stored and committed on this device." +
                 " Recipients are picked from OpenKeyChain before creating. A remote can be" +
                 " attached later from Setup.",
                style = MaterialTheme.typography.bodySmall)
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
                onClick = { onNewVault() },
                enabled = recipientIds.isNotEmpty(),
                modifier = Modifier.fillMaxWidth()
            ) { Text("Create local-only vault") }
        } else {
            // 1. Load sources first.
            Text("Load vault from", style = MaterialTheme.typography.titleSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { onLoadGitHub(remote.trim(), emptyList(), if (loadAuth == "pat") pat.trim() else "") },
                    modifier = Modifier.weight(1f)
                ) { Text("GitHub") }
                OutlinedButton(
                    onClick = { onLoadUsb() },
                    modifier = Modifier.weight(1f)
                ) { Text("USB file") }
                OutlinedButton(
                    onClick = { importPicker.launch(arrayOf("*/*")) },
                    modifier = Modifier.weight(1f)
                ) { Text("Proton export") }
            }

            // 2. Sync-auth type for the GitHub transport.
            Text("GitHub sync auth", style = MaterialTheme.typography.titleSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    modifier = Modifier.weight(1f),
                    selected = loadAuth == VaultSession.SSH_SYNC_SCREENLOCK,
                    onClick = {
                        loadAuth = VaultSession.SSH_SYNC_SCREENLOCK
                        if (!remote.startsWith("git@") && !remote.startsWith("ssh://"))
                            remote = "git@github.com:"
                    },
                    label = { Text("Screenlock SSH", maxLines = 1) }
                )
                FilterChip(
                    modifier = Modifier.weight(1f),
                    selected = loadAuth == VaultSession.SSH_SYNC_YUBIKEY,
                    onClick = {
                        loadAuth = VaultSession.SSH_SYNC_YUBIKEY
                        if (!remote.startsWith("git@") && !remote.startsWith("ssh://"))
                            remote = "git@github.com:"
                    },
                    label = { Text("YubiKey SSH", maxLines = 1) }
                )
                FilterChip(
                    modifier = Modifier.weight(1f),
                    selected = loadAuth == "pat",
                    onClick = {
                        loadAuth = "pat"
                        if (!remote.startsWith("https://") && !remote.startsWith("http://"))
                            remote = "https://github.com/"
                    },
                    label = { Text("PAT (HTTPS)", maxLines = 1) }
                )
            }
            OutlinedTextField(
                value = remote, onValueChange = { remote = it },
                label = { Text("GitHub remote (HTTPS, or git@ for SSH)") }, singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            when (loadAuth) {
                VaultSession.SSH_SYNC_SCREENLOCK -> {
                    // The clone handshake signs with the SSH key: it must be
                    // enrolled BEFORE loading (screenlock-gated).
                    Text("The clone authenticates with this device's screenlock " +
                        "SSH key — enroll it first, then add it on GitHub as a " +
                        "deploy key (write access).", style = MaterialTheme.typography.bodySmall)
                    Button(onClick = onShowSshKey, modifier = Modifier.fillMaxWidth()) {
                        Text("Create & show public key")
                    }
                }
                VaultSession.SSH_SYNC_YUBIKEY -> {
                    Text("The clone authenticates with the YubiKey's OpenPGP auth " +
                        "subkey via OpenKeyChain — the key already enrolled in " +
                        "GitHub from desktop pushes (each load asks for the touch).",
                        style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(
                        value = sshLine, onValueChange = { sshLine = it },
                        label = { Text("OpenSSH public line (gpg --export-ssh-key)") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = subkeyId, onValueChange = { subkeyId = it },
                        label = { Text("Auth subkey key id (16 hex)") }, singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
                "pat" -> OutlinedTextField(
                    value = pat, onValueChange = { pat = it },
                    label = { Text("Fine-grained PAT (deprecated; stored encrypted)") },
                    singleLine = true,
                    visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
            }

            // 3. The final action: completes the load with the chosen auth
            // (enabled once the auth's inputs are filled). Recipients are
            // NOT configured here: the loaded repo carries its recipients
            // (keys/*.public.asc, seeded into Setup on load).
            val loadReady = when (loadAuth) {
                VaultSession.SSH_SYNC_SCREENLOCK -> true // the key self-generates via the QR flow
                VaultSession.SSH_SYNC_YUBIKEY -> sshLine.contains(" ") && subkeyId.trim().length == 16
                else -> pat.isNotBlank()
            }
            Button(
                onClick = {
                    onLoadGitHub(remote.trim(), emptyList(), if (loadAuth == "pat") pat.trim() else "")
                },
                enabled = loadReady,
                modifier = Modifier.fillMaxWidth()
            ) { Text("Load from GitHub") }
            Text(
                "Recipients are NOT configured here: the loaded repo carries its " +
                    "recipients (keys/*.public.asc, seeded into Setup on load).",
                style = MaterialTheme.typography.bodySmall
            )
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
