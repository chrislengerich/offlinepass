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
import androidx.compose.runtime.saveable.rememberSaveable
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
    onPickAuthSubkey: () -> Unit = {},
    onSshSelfTest: () -> Unit = {},
    onEnrollYubikeySsh: (sshLine: String, subkeyId: String) -> Unit = { _, _ -> },
    onClearStatus: () -> Unit = {}
) {
    // Field state lives on the VaultSession singleton (see the drafts note
    // there): this ROM recreates activities aggressively enough that
    // composition-scoped state doesn't survive the chip switches / QR detour.
    var remote by VaultSession.loadRemoteState
    var pat by VaultSession.loadPatState
    var mode by rememberSaveable { mutableStateOf("load") }
    var loadAuth by VaultSession.loadAuthState
    var sshLine by VaultSession.loadSshLineState
    var subkeyId by VaultSession.loadSubkeyIdState
    // One-time blank defaults (converges; the user's values win afterwards).
    if (remote.isBlank()) {
        // Default is the URL per the DEFAULT sync-auth choice: an https
        // default viewed as an SSH choice becomes the git@ form.
        val default = if (VaultSession.sshSyncMode() != "pat" &&
            defaultRemote.startsWith("https://")
        ) defaultRemote.replaceFirst("https://", "git@").replaceFirst("/", ":")
        else defaultRemote
        remote = default
    }
    if (pat.isBlank()) pat = prefillPat
    if (loadAuth.isBlank()) loadAuth = VaultSession.sshSyncMode()

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
                        onClearStatus()
                        loadAuth = VaultSession.SSH_SYNC_SCREENLOCK
                        remote = VaultSession.convertRemote(remote, "ssh")
                    },
                    label = { Text("Screenlock SSH", maxLines = 1) }
                )
                FilterChip(
                    modifier = Modifier.weight(1f),
                    selected = loadAuth == VaultSession.SSH_SYNC_YUBIKEY,
                    onClick = {
                        onClearStatus()
                        loadAuth = VaultSession.SSH_SYNC_YUBIKEY
                        remote = VaultSession.convertRemote(remote, "ssh")
                    },
                    label = { Text("GPG (Yubikey)", maxLines = 1) }
                )
                FilterChip(
                    modifier = Modifier.weight(1f),
                    selected = loadAuth == "pat",
                    onClick = {
                        onClearStatus()
                        loadAuth = "pat"
                        remote = VaultSession.convertRemote(remote, "pat")
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
                    Text("The clone authenticates with a GPG key via OpenKeychain — " +
                        "any signing-capable subkey of a key OpenKeychain holds: " +
                        "a software key on this phone, or a hardware key (e.g., " +
                        "YubiKey; each sync asks for the touch). GitHub must have " +
                        "the same OpenSSH line enrolled (deploy key with write " +
                        "access, or the account SSH key).",
                        style = MaterialTheme.typography.bodySmall)
                    Button(onClick = onPickAuthSubkey, modifier = Modifier.fillMaxWidth()) {
                        Text("Choose key in OpenKeyChain")
                    }
                    TextButton(onClick = onSshSelfTest) {
                        Text("Run SSH auth self-test")
                    }
                    OutlinedTextField(
                        value = subkeyId, onValueChange = { subkeyId = it },
                        label = { Text("Subkey key id (auto-filled by the picker)") },
                        singleLine = true,
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
            // TEMPORARY diagnostic: the load button's gate inputs, on screen.
            Text(
                "auth=$loadAuth, keyIdLen=${subkeyId.trim().length}, " +
                    "lineLen=${sshLine.length}, idPicked=${VaultSession.pickedAuthSubkeyId != null}, " +
                    "lineDraft=${VaultSession.yubikeySshLineDraft != null}",
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                "Recipients are NOT configured here: the loaded repo carries its " +
                    "recipients (keys/*.public.asc, seeded into Setup on load).",
                style = MaterialTheme.typography.bodySmall
            )
        }
        if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodyMedium)
    }
}

/** The OpenPGP applet's user PIN (YubiKit card signing): shown when a
 *  signature needs it, once per identity session; never stored. */
@Composable
fun PinPromptDialog(onPin: (String?) -> Unit) {
    var pinInput by remember { mutableStateOf("") }
    androidx.compose.material3.AlertDialog(
        onDismissRequest = { onPin(null) },
        title = { Text("Security key PIN") },
        text = {
            Column {
                Text(
                    "The OpenPGP card's PIN unlocks the signature " +
                        "(the card holds the signing key).",
                    style = MaterialTheme.typography.bodySmall
                )
                OutlinedTextField(
                    value = pinInput, onValueChange = { pinInput = it },
                    label = { Text("PIN") },
                    singleLine = true,
                    visualTransformation = androidx.compose.ui.text.input
                        .PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            Button(onClick = { onPin(pinInput) }, enabled = pinInput.isNotBlank()) {
                Text("OK")
            }
        },
        dismissButton = {
            TextButton(onClick = { onPin(null) }) { Text("Cancel") }
        }
    )
}

/** Entry gate (screenlock toggle on): a screenlock prompt is required
 *  before ANY content — fresh app start or after the idle timeout. A
 *  success reveals the sealed list; a decline keeps the gate up. */
@Composable
fun LockGateScreen(
    status: String,
    busy: String?,
    onUnlock: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(64.dp))
        Text("offlinepass", style = MaterialTheme.typography.headlineSmall)
        Text("Locked", style = MaterialTheme.typography.titleMedium)
        Text(
            "The screen lock is required to continue " +
                "(biometric or device PIN).",
            style = MaterialTheme.typography.bodyMedium
        )
        Button(onClick = onUnlock, enabled = busy == null) {
            Text(busy ?: "Unlock")
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
