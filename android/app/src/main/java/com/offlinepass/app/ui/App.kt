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
    /** Post-create onboarding: the security key, the remote (+ the first
     *  sync publishing the key material), the screenlock — all skippable,
     *  re-openable from Setup while the remote is unattached. */
    object GetStarted : Screen()
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
    onLoadBackupZip: () -> Unit = {},
    onEnrollFromGithubKeys: () -> Unit = {},
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
    // Bootstrap pulls authenticate with the SECURITY KEY only — the
    // screenlock is never the bootstrap key (it is enrolled later, as a
    // first-class local signer, after the repo exists).
    if (loadAuth.isBlank()) loadAuth = VaultSession.SSH_SYNC_YUBIKEY

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
            FilterChip(selected = mode == "import", onClick = { mode = "import" }, label = { Text("Import") })
            FilterChip(selected = mode == "new", onClick = { mode = "new" }, label = { Text("New vault") })
        }

        if (mode == "new") {
            Text("New vault — local-only: everything is stored and committed on this device." +
                 " Recipients are picked from OpenKeyChain before creating. A remote can be" +
                 " attached later from Setup.",
                style = MaterialTheme.typography.bodySmall)
            RecipientsEditor(recipientIds, onPickRecipients, onRemoveRecipient)
            Button(
                onClick = { onNewVault() },
                enabled = recipientIds.isNotEmpty(),
                modifier = Modifier.fillMaxWidth()
            ) { Text("Create local-only vault") }
        } else if (mode == "import") {
            // Import = a FOREIGN format (a Proton export); the vault material
            // from this app's own format travels via Load existing.
            Text("Import a Proton export — pick the recipients (who can open " +
                "the imported entries) first, then the export file.",
                style = MaterialTheme.typography.bodySmall)
            RecipientsEditor(recipientIds, onPickRecipients, onRemoveRecipient)
            Button(
                onClick = { importPicker.launch(arrayOf("*/*")) },
                enabled = recipientIds.isNotEmpty(),
                modifier = Modifier.fillMaxWidth()
            ) { Text("From Proton export") }
        } else {
            // 1. Load sources first.
            Text("Load vault from", style = MaterialTheme.typography.titleSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { onLoadGitHub(remote.trim(), emptyList(), "") },
                    modifier = Modifier.weight(1f)
                ) { Text("GitHub") }
                OutlinedButton(
                    onClick = { onLoadUsb() },
                    modifier = Modifier.weight(1f)
                ) { Text("USB file") }
                OutlinedButton(
                    onClick = { onLoadBackupZip() },
                    modifier = Modifier.weight(1f)
                ) { Text("Backup zip") }
            }

            // 2. Sync-auth: the security key only (the card signs the SSH
            // handshake via YubiKit - no PAT, no screenlock key at
            // bootstrap).
            Text("GitHub sync auth", style = MaterialTheme.typography.titleSmall)
            Text("The clone authenticates with the security key (YubiKey): " +
                "the card signs the SSH handshake directly - PIN + touch. " +
                "GitHub must have the enrolled OpenSSH line (deploy key or " +
                "account key).", style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(
                value = remote, onValueChange = { remote = it },
                label = { Text("GitHub remote (HTTPS, or git@ for SSH)") }, singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Button(onClick = onEnrollFromGithubKeys, modifier = Modifier.fillMaxWidth()) {
                Text("Enroll from GitHub keys (one touch)")
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

            // 3. The final action: completes the load with the chosen auth
            // (enabled once the auth's inputs are filled). Recipients are
            // NOT configured here: the loaded repo carries its recipients
            // (keys/*.public.asc, seeded into Setup on load).
            val loadReady = sshLine.contains(" ") && subkeyId.trim().length == 16
            Button(
                onClick = { onLoadGitHub(remote.trim(), emptyList(), "") },
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

/** The OpenPGP applet's user PIN (YubiKit card signing): shown when a
 *  signature needs it, once per identity session; never stored. */
/** The recipient picking shared by New vault and Import: the entries are
 *  encrypted to these keys, so they must be chosen before create/import —
 *  and the security key must be set up in OpenKeyChain first, since the
 *  picker lists OpenKeyChain's keys. */
@Composable
private fun RecipientsEditor(
    recipientIds: List<Long>,
    onPickRecipients: () -> Unit,
    onRemoveRecipient: (Long) -> Unit
) {
    Text("Before adding a recipient: set up the security key in " +
        "OpenKeyChain — import the key (the public key at minimum) and " +
        "pair the security key (OpenKeyChain menu → Manage Smart Card), " +
        "so the picker lists the encryption subkey to encrypt to.",
        style = MaterialTheme.typography.bodySmall)
    Text("Recipients (from OpenKeyChain picker)", style = MaterialTheme.typography.titleSmall)
    if (recipientIds.isEmpty()) {
        Text("(none — pick at least one before creating/importing)",
            style = MaterialTheme.typography.bodySmall)
    }
    recipientIds.forEach { id ->
        Row(modifier = Modifier.fillMaxWidth(),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            Text("0x%016X".format(id), modifier = Modifier.weight(1f))
            TextButton(onClick = { onRemoveRecipient(id) }) { Text("Remove") }
        }
    }
    Button(onClick = onPickRecipients, enabled = true, modifier = Modifier.fillMaxWidth()) {
        Text("Add recipient (pick in OpenKeyChain)")
    }
}

/** Post-create onboarding: three skippable steps, each backed by the
 *  existing Setup machinery; the remote step's first sync publishes the
 *  repo's key material (meta/devices.json + keys/). */
@Composable
fun GetStartedScreen(
    status: String,
    busy: String?,
    remoteAttached: Boolean,
    yubikeyEnrolled: Boolean,
    screenlockEnrolled: Boolean,
    okkInstalled: Boolean,
    sshAuthUseAut: Boolean = false,
    onSshAuthUseAut: (Boolean) -> Unit = {},
    onEnrollFromGithubKeys: () -> Unit,
    onConnectAndSync: (String) -> Unit,
    onEnrollScreenlock: () -> Unit,
    onImportToOkk: () -> Unit,
    onShowSshKey: () -> Unit,
    onDone: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("Get started", style = MaterialTheme.typography.headlineSmall)
        Text("Every step is skippable and stays available in Settings.",
            style = MaterialTheme.typography.bodySmall)

        // The owner/repo is NOT asked here: the load-existing flow configures
        // the remote and seeds the connect draft (the enrollment's username
        // derives from it). This screen = the post-load checklist.
        Text("1. Security key (SSH auth)", style = MaterialTheme.typography.titleSmall)
        if (yubikeyEnrolled) {
            Text("✅ Enrolled — every sync authenticates with the card (PIN + touch).",
                style = MaterialTheme.typography.bodySmall)
            // The card slot: the SIG subkey (the default — the card pads the
            // digest) vs the AUT subkey (the dedicated authentication key —
            // the raw-RSA challenge, the caller pads; the transport is the
            // experiment). The switch = the pref the cardSign reads.
            androidx.compose.material3.ListItem(
                headlineContent = { Text("Use the AUT key for SSH auth") },
                supportingContent = { Text("The dedicated authentication subkey " +
                    "(the raw-RSA challenge, the caller pads — the transport " +
                    "experiment). Off = the SIG signing subkey.") },
                trailingContent = {
                    androidx.compose.material3.Switch(
                        checked = sshAuthUseAut,
                        onCheckedChange = onSshAuthUseAut)
                })
        } else {
            Text("The card's SSH line must be on GitHub (an account key), then " +
                "the app matches it against the card with one touch.",
                style = MaterialTheme.typography.bodySmall)
            Button(
                onClick = {
                    // Commit the field FIRST: the enrollment derives the
                    // username from the draft — a stale draft enrolled the
                    // wrong user's keys.
                    // The draft = seeded by the load flow (the configured
                    // remote); the enrollment derives the username from it.
                    val draft = VaultSession.connectDraftOwnerRepo() ?: ""
                    if (draft.contains("/") && !draft.startsWith("/") &&
                        !draft.endsWith("/")
                    ) {
                        VaultSession.saveConnectDraft(draft, "ssh")
                        VaultSession.loadRemoteState.value = "git@github.com:$draft"
                        onEnrollFromGithubKeys()
                    }
                },
                enabled = busy == null,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Enroll from GitHub keys (one touch)")
            }
        }
        HorizontalDivider()

        Text("2. Attach a GitHub remote", style = MaterialTheme.typography.titleSmall)
        if (remoteAttached) {
            Text("✅ Remote attached — the key material is published in the repo.",
                style = MaterialTheme.typography.bodySmall)
        } else {
            Text("The first sync commits meta/devices.json + keys/ — the repo " +
                "becomes the offline keyring for new devices. Uses the " +
                "repository from step 0.",
                style = MaterialTheme.typography.bodySmall)
            Button(
                onClick = {
                    val draft = VaultSession.connectDraftOwnerRepo() ?: ""
                    if (draft.isNotBlank()) onConnectAndSync("git@github.com:$draft")
                },
                enabled = busy == null &&
                    !VaultSession.connectDraftOwnerRepo().isNullOrBlank(),
                modifier = Modifier.fillMaxWidth()
            ) { Text("Connect & sync") }
        }
        HorizontalDivider()

        Text("3. Screenlock protection (signing + at-rest encryption)",
            style = MaterialTheme.typography.titleSmall)
        if (screenlockEnrolled) {
            Text("✅ Enrolled — commits sign with this device's screenlock key.",
                style = MaterialTheme.typography.bodySmall)
        } else {
            Text("Commits sign with this device's key (every save prompts the " +
                "screen lock), and the item secrets are encrypted at rest " +
                "behind the screen lock (the sealed cache — on by default, " +
                "togglable in Settings). The public key pairs on GitHub " +
                "out-of-band.",
                style = MaterialTheme.typography.bodySmall)
            Button(onClick = onEnrollScreenlock, enabled = busy == null,
                modifier = Modifier.fillMaxWidth()) {
                Text("Enroll screenlock signing")
            }
            TextButton(onClick = onShowSshKey, enabled = busy == null) {
                Text("Show the public key (to add on GitHub)")
            }
        }
        HorizontalDivider()
        // Step 4 = optional OpenKeyChain integration: offered ONLY when OKK
        // is installed. The import stages the repo's key material (the
        // sign + the encrypt public keys) into OKK — the redundancy for
        // the legacy paths (the USB restore, the future re-imports), never
        // required for the daily sync/save (the card does those).
        if (okkInstalled) {
            Text("4. OpenKeyChain (optional)",
                style = MaterialTheme.typography.titleSmall)
            Text("Import the vault's key material into OpenKeyChain — a " +
                "backup decrypt/sign path for other apps and the USB " +
                "restore. The daily flow (the card + the screenlock) " +
                "never needs it.",
                style = MaterialTheme.typography.bodySmall)
            Button(onClick = onImportToOkk, enabled = busy == null,
                modifier = Modifier.fillMaxWidth()) {
                Text("Import keys into OpenKeyChain")
            }
        }
        HorizontalDivider()
        Button(onClick = onDone, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Done for now")
        }
        if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodyMedium)
    }
}

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
    sealedAvailable: Boolean,
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
        if (sealedAvailable) {
            Text(
                "The screen lock is required to continue " +
                    "(biometric or device PIN).",
                style = MaterialTheme.typography.bodyMedium
            )
        } else {
            // The sealed cache is missing/stale (the last seal failed or
            // none ran yet): the screenlock can't open it — the security
            // key is the gate until the next successful seal.
            Text(
                "The sealed cache is unavailable — unlocking requires " +
                    "your security key (touch + PIN). The screen lock " +
                    "protection resumes after the next unlock.",
                style = MaterialTheme.typography.bodyMedium
            )
        }
        Button(onClick = onUnlock, enabled = busy == null) {
            Text(busy ?: "Unlock")
        }
        if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodyMedium)
    }
}

/** Locked state: one button, one security-key touch. (The PAT flow is
 *  backend-only now: HTTPS remotes keep working where configured, but the
 *  UI never asks for a token.) */
@Composable
fun UnlockScreen(
    status: String,
    busy: String?,
    onUnlock: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(48.dp))
        Text("Vault locked", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Unlocking requires your hardware key (touch + PIN).",
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
