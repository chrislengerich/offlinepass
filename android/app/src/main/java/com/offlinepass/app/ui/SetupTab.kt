package com.offlinepass.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.offlinepass.app.vault.VaultSession

/**
 * The persistent Setup tab (user_flows.md): sync/remote config, identities,
 * USB save/restore, autofill enablement, QRFT export entry point.
 * Scrolls — the content exceeds one screen.
 */
@Composable
fun SetupTabScreen(
    status: String,
    busy: String?,
    onBack: () -> Unit,
    onTestSync: () -> Unit,
    onResetRepo: () -> Unit,
    onExportRepoQrft: () -> Unit = {},
    onUsbRestore: () -> Unit,
    onEnableAutofill: () -> Unit,
    onForget: () -> Unit,
    autofillEnabled: Boolean,
    recipientIds: List<Long>,
    onAddRecipient: () -> Unit,
    onAddCardRecipient: () -> Unit = {},
    onRemoveRecipient: (Long) -> Unit,
    signerLabel: String,
    onPickSigner: () -> Unit,
    onClearSigner: () -> Unit,
    onUseYubikeySigner: () -> Unit,
    onRemoveScreenlock: () -> Unit,
    onSetDeviceName: (String) -> Unit,
    onInitOkkFromRepo: () -> Unit,
    onGetStarted: () -> Unit,
    deviceCredentialReady: Boolean = true,
    onEnrollScreenlock: () -> Unit = {},
    screenLockOn: Boolean,
    onScreenLockToggle: (Boolean) -> Unit,
    idleLockOn: Boolean = false,
    onIdleLockToggle: (Boolean) -> Unit = {},
    autoLockSeconds: Int = 300,
    onAutoLockChange: (Int) -> Unit = {},
    screenlockUnlockOn: Boolean = false,
    onScreenlockUnlockToggle: (Boolean) -> Unit = {},
    onLock: () -> Unit,
    onExportBackupZip: () -> Unit = {},
    onExportProton: () -> Unit = {},
    onImportQrft: () -> Unit,
    onPairDevice: () -> Unit = {},
    pairedDevices: List<com.offlinepass.app.vault.DeviceRecord> = emptyList(),
    onShowDeviceQr: (com.offlinepass.app.vault.DeviceRecord) -> Unit = {},
    onShowSshKey: () -> Unit = {},
    onEnrollFromGithubKeys: () -> Unit = {},
    onRotateSshKey: () -> Unit = {},
    onRemoveYubikeySsh: () -> Unit = {},
    onEnrollYubikeySsh: (String, String) -> Unit = { _, _ -> },
    onPickAuthSubkey: () -> Unit = {},
    selfTestResult: String? = null,
    onSshSelfTest: () -> Unit = {},
    onShowGithubAuthKey: () -> Unit = {},
    onRemoveDevice: (String) -> Unit = {},
    securityKeyLabels: List<String> = emptyList(),
    onSetSecurityKeyName: () -> Unit = {},
    tempRecipientLabel: String? = null,
    onScanTempRecipient: () -> Unit = {},
    onShowDeviceKey: () -> Unit = {},
    onExportTempUsb: () -> Unit = {},
    onExportTempQrft: () -> Unit = {}
) {
    val cfg = VaultSession.config()
    var confirmDialog by remember { mutableStateOf<String?>(null) }
    var deviceNameDialog by remember { mutableStateOf<String?>(null) }
    deviceNameDialog?.let { pre ->
        var nameInput by androidx.compose.runtime.remember(pre) {
            androidx.compose.runtime.mutableStateOf(pre)
        }
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { deviceNameDialog = null },
            title = { Text("Name this device") },
            text = {
                androidx.compose.material3.OutlinedTextField(
                    value = nameInput, onValueChange = { nameInput = it },
                    label = { Text("Device name") }, singleLine = true)
            },
            confirmButton = {
                TextButton(onClick = {
                    val v = nameInput
                    deviceNameDialog = null
                    if (v.isNotBlank()) onSetDeviceName(v)
                }) { Text("Set") }
            },
            dismissButton = {
                TextButton(onClick = { deviceNameDialog = null }) { Text("Cancel") }
            }
        )
    }

    confirmDialog?.let { what ->
        AlertDialog(
            onDismissRequest = { confirmDialog = null },
            title = { Text("Confirm reset") },
            text = {
                Text("Wipe the local git clone and re-clone from the remote?\n\n" +
                    // The divergence against the last-fetched origin/main —
                    // computed once per remote change (a local git read, no
                    // network, no touch prompt).
                    (remember(cfg?.remoteUrl) { VaultSession.resetRemoteWarning() }))
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmDialog = null
                    onResetRepo()
                }) { Text("Reset") }
            },
            dismissButton = {
                TextButton(onClick = { confirmDialog = null }) { Text("Cancel") }
            }
        )
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("← Back") }
            Text("Setup", style = MaterialTheme.typography.titleLarge)
        }
        Text("Remote: ${cfg?.remoteUrl ?: "(none — local-only)"}")
        // The head hash is read straight from the repo — the same front-7
        // the Recent commits list shows (NOT the device id, which looks
        // deceptively like a commit hash).
        Text(
            "Commit: ${VaultSession.headCommitShort()}   Rev: ${VaultSession.currentRev()}",
            style = MaterialTheme.typography.bodySmall
        )

        // Local-only vault: offer to attach a remote (git-synced backup +
        // cross-device sync) without touching the local history.
        // Auto-reopen the connect dialog when a draft exists (the SSH-key QR
        // detour returns here to finish the flow).
        if (cfg?.remoteUrl == null) {
            Text("Local-only: entries commit on this device only. " +
                "Attach a remote via Get started.",
                style = MaterialTheme.typography.bodySmall)
            Button(onClick = onGetStarted, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
                Text("Get started (the setup checklist)")
            }
            if (VaultSession.sshSyncMode() == VaultSession.SSH_SYNC_YUBIKEY) {
                Text("YubiKey SSH enrolled — every sync asks for the YubiKey touch.",
                    style = MaterialTheme.typography.bodySmall)
            }
            Text(
                "Connect remote: pick Screenlock SSH key (the QR enrolls this device's " +
                    "key as a GitHub deploy key — syncs then open with the screen lock) " +
                    "or PAT (HTTPS + fine-grained token). " +
                    "YubiKey SSH: paste the auth subkey's OpenSSH line (desktop: gpg --export-ssh-key) " +
                    "and its key id — every sync asks for the YubiKey touch.",
                style = MaterialTheme.typography.bodySmall
            )
        }
        // Sync state lives directly with its button.
        // The commit summaries = the LOCAL-ONLY too (the git history = on-device).
        val commits = VaultSession.recentCommits()
        if (commits.isNotEmpty()) {
            Text(
                (if (cfg?.remoteUrl != null)
                    "Sync: ${VaultSession.syncStatus ?: "not synced this session"}"
                else "Local-only vault (no remote attached)") +
                    VaultSession.syncDivergenceText().let { if (it.isEmpty()) "" else " — $it" },
                style = MaterialTheme.typography.bodySmall
            )
            if (cfg?.remoteUrl != null) {
                Button(onClick = onTestSync, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
                    Text("Sync now (fetch/push)")
                }
            }
            Text("Recent commits:", style = MaterialTheme.typography.labelSmall)
            commits.forEach { c ->
                Text(
                    c,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 1
                )
            }
            if (cfg?.remoteUrl != null) {
                Button(
                    onClick = { confirmDialog = "repo" },
                    enabled = busy == null,
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Reset local repo (wipe + re-clone)") }
            }
        } else if (cfg?.remoteUrl != null) {
            Text(
                "Sync: ${VaultSession.syncStatus ?: "not synced this session"}",
                style = MaterialTheme.typography.bodySmall
            )
            Button(onClick = onTestSync, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
                Text("Sync now (fetch/push)")
            }
            Button(
                onClick = { confirmDialog = "repo" },
                enabled = busy == null,
                modifier = Modifier.fillMaxWidth()
            ) { Text("Reset local repo (wipe + re-clone)") }
        }
        HorizontalDivider()

        Text("Share vault", style = MaterialTheme.typography.titleSmall)

        Text("Recipients", style = MaterialTheme.typography.labelLarge)
        Text(
            if (tempRecipientLabel == null) "(no scanned key — exports go to the permanent recipients only)"
            else "Scanned: $tempRecipientLabel (session only; exports include it)",
            style = MaterialTheme.typography.bodySmall
        )
        if (VaultSession.recipientKeyIds().isEmpty())
            Text("(no permanent recipients)", style = MaterialTheme.typography.bodySmall)
        VaultSession.recipientKeyIds().forEach { id ->
            Text("0x%016X".format(id), style = MaterialTheme.typography.bodySmall)
        }
        Button(onClick = onScanTempRecipient, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Scan key")
        }
        Button(onClick = onShowDeviceKey, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Show key")
        }

        Row(modifier = Modifier.fillMaxWidth(),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            Checkbox(checked = VaultSession.exportEncrypted, onCheckedChange = {
                VaultSession.exportEncrypted = it
            })
            Text(
                "Encrypt the vault export" +
                    if (VaultSession.exportEncrypted) ""
                    else " — OFF: the export is PLAINTEXT (anyone with the file reads everything)",
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodySmall
            )
        }

        Text("USB", style = MaterialTheme.typography.labelLarge)
        Button(onClick = onExportTempUsb, enabled = busy == null,
            modifier = Modifier.fillMaxWidth()) {
            Text("Export")
        }
        Button(onClick = onUsbRestore, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Import")
        }

        Text("QRFT", style = MaterialTheme.typography.labelLarge)
        Button(onClick = onExportTempQrft, enabled = busy == null,
            modifier = Modifier.fillMaxWidth()) {
            Text("Export")
        }
        Button(onClick = onImportQrft, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Import")
        }

        HorizontalDivider()
        Text("Backups", style = MaterialTheme.typography.titleSmall)
        // The backup exports carry the WHOLE REPO (the git-state clone —
        // the vault + the keys + the signed history); the repo export
        // supersedes the vault-snapshot. The imports live in Share.
        Text("USB", style = MaterialTheme.typography.labelLarge)
        Button(onClick = onExportBackupZip, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Export")
        }
        Text("QRFT", style = MaterialTheme.typography.labelLarge)
        Button(onClick = onExportRepoQrft, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Export")
        }

        HorizontalDivider()

        // THIS device + the repo's registered devices: one section — the
        // device-level view of the sync.
        Text("Devices", style = MaterialTheme.typography.titleSmall)
        Text("This device", style = MaterialTheme.typography.labelLarge)
        Text("Name: ${VaultSession.deviceName()}", style = MaterialTheme.typography.bodySmall)
        Button(onClick = { deviceNameDialog = VaultSession.deviceName() },
            enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Set device name")
        }

        Text("Security keys", style = MaterialTheme.typography.labelLarge)
        if (securityKeyLabels.isEmpty())
            Text("(none known — plug a key in and set its name)",
                style = MaterialTheme.typography.bodySmall)
        securityKeyLabels.forEach {
            Text(it, style = MaterialTheme.typography.bodySmall)
        }
        Button(onClick = onSetSecurityKeyName, enabled = busy == null,
            modifier = Modifier.fillMaxWidth()) {
            Text("Set security key name")
        }
        if (cfg?.remoteUrl != null) {
            Text("Registered", style = MaterialTheme.typography.labelLarge)
            val devices = VaultSession.deviceListLabels()
            if (devices.isEmpty()) {
                Text("(no devices registered yet — the first sync adds this device)",
                    style = MaterialTheme.typography.bodySmall)
            } else {
                devices.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
        }
        HorizontalDivider()
        Text("Vault encryption keys", style = MaterialTheme.typography.titleSmall)
        if (recipientIds.isEmpty()) {
            Text("(none — add one before saving)", style = MaterialTheme.typography.bodySmall)
        }
        recipientIds.forEach { id ->
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                Text("0x%016X".format(id), modifier = Modifier.weight(1f))
                TextButton(onClick = { onRemoveRecipient(id) }) { Text("Remove") }
            }
        }
        Button(onClick = onAddCardRecipient, enabled = busy == null,
            modifier = Modifier.fillMaxWidth()) {
            Text("Add the attached card as a recipient")
        }
        TextButton(onClick = onAddRecipient, enabled = busy == null,
            modifier = Modifier.fillMaxWidth()) {
            Text("Add recipient (pick in OpenKeyChain)")
        }
        HorizontalDivider()

        // THE SHARE SECTION: how a vault moves between people. A scanned
        // key lives in the session only — appended to the export's
        // recipient set (the permanent recipients stay first) and never
        // written to the repo's keys/ or config. "Show key" publishes this
        // device's own public key as a QRFT for the other side to scan.
        // Signing is its own section — the OpenKeyChain initialization
        // (seeding the repo's keys into OKK) belongs with it, not with the
        // device identity.
        Text("Commit signer", style = MaterialTheme.typography.titleSmall)
        if (VaultSession.commitSigningMode() == VaultSession.SIGNING_SCREENLOCK) {
            // Screenlock mode: OpenKeyChain signing is not used at all.
            Text(
                "Screen lock (keystore key " +
                    com.offlinepass.app.crypto.KeystoreSigner.publicKeyFingerprint() + ") — " +
                    "every save prompts for the screen lock; OpenKeyChain is not involved.",
                style = MaterialTheme.typography.bodySmall
            )
            if (VaultSession.yubikeyAuthSubkeyId() != null) {
                Button(
                    onClick = onUseYubikeySigner,
                    enabled = busy == null,
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Use the YubiKey (touch to sign)") }
            }
            // THE SAME SWITCH: using the YubiKey IS removing screenlock
            // signing — one button, one action (the modes are exclusive).
        } else if (VaultSession.commitSigningMode() == VaultSession.SIGNING_YUBIKEY) {
            Text(
                "YubiKey (SIG slot subkey 0x" +
                    (VaultSession.yubikeyAuthSubkeyId()
                        ?.let { "%016X".format(it) } ?: "?") +
                    ") — every save prompts for the OpenPGP PIN and the touch.",
                style = MaterialTheme.typography.bodySmall
            )
            Button(
                onClick = onEnrollScreenlock,
                enabled = busy == null && deviceCredentialReady,
                modifier = Modifier.fillMaxWidth()
            ) { Text("Re-enable screenlock signing") }
        } else {
            Text("Signer: $signerLabel", style = MaterialTheme.typography.bodySmall)
            Button(onClick = onPickSigner, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
                Text("Pick signing key (OpenKeyChain)")
            }
            TextButton(onClick = onClearSigner, enabled = VaultSession.signingKeyId() != null) {
                Text("Use default (first recipient)")
            }
            Button(
                onClick = onEnrollScreenlock,
                enabled = busy == null && deviceCredentialReady,
                modifier = Modifier.fillMaxWidth()
            ) { Text("Enroll screenlock signing (alternative)") }
            if (!deviceCredentialReady) Text(
                "Enroll a screen lock (PIN/pattern) first — the signer is gated by it.",
                style = MaterialTheme.typography.bodySmall
            )
            if (VaultSession.yubikeyAuthSubkeyId() != null) {
                Button(
                    onClick = onUseYubikeySigner,
                    enabled = busy == null,
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Use the YubiKey (touch to sign)") }
            }
        }
        HorizontalDivider()

        Text("Deployment (SSH sync identities)", style = MaterialTheme.typography.titleSmall)
        val sshFp = remember {
            runCatching {
                com.offlinepass.app.crypto.SshKeyManager().ensureKeyPair().fingerprint
            }.getOrNull()
        }
        if (sshFp != null) {
            Text("Screenlock key: $sshFp (60s screenlock gate)", style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = onRotateSshKey, enabled = busy == null) {
                Text("Rotate key (re-add the deploy key after)")
            }
        } else {
            Text("Screenlock SSH key: not enrolled.", style = MaterialTheme.typography.bodySmall)
        }
        val ykLine = VaultSession.yubikeySshLine()
        if (ykLine != null) {
            val ykFp = remember(ykLine) {
                runCatching {
                    com.offlinepass.app.crypto.PgpSshBridge.fingerprintOf(ykLine)
                }.getOrNull()
            }
            Text("YubiKey auth subkey: ${ykFp ?: "(line unparseable)"}", style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = onSshSelfTest, enabled = busy == null) {
                Text("Run SSH auth self-test")
            }
            // The verdict INLINE (the bottom Log is easy to miss): a
            // no-keys failure points at Show auth key for GitHub.
            selfTestResult?.let {
                Text(it, style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = onShowGithubAuthKey, enabled = busy == null) {
                Text("Show auth key for GitHub")
            }
            TextButton(onClick = onRemoveYubikeySsh, enabled = busy == null) {
                Text("Remove")
            }
        } else {
            Text("YubiKey SSH: not enrolled.", style = MaterialTheme.typography.bodySmall)
        }
        Text("Active mode: " + VaultSession.sshSyncMode(), style = MaterialTheme.typography.bodySmall)
        HorizontalDivider()

        HorizontalDivider()

        Text("Export", style = MaterialTheme.typography.titleSmall)
        Button(onClick = onExportProton, enabled = busy == null,
            modifier = Modifier.fillMaxWidth()) {
            Text("To Proton (plaintext JSON)")
        }
        HorizontalDivider()

        Text("Paste devices (Chrome extension)", style = MaterialTheme.typography.titleSmall)
        Button(onClick = onPairDevice, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Pair paste device (scan extension QR)")
        }
        if (pairedDevices.isEmpty()) {
            Text(
                "None paired. In the browser extension, choose \"Pair a security key\" " +
                    "and scan its QR with \"Import from QRFT\" above.",
                style = MaterialTheme.typography.bodySmall
            )
        }
        pairedDevices.forEach { device ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(device.name)
                    Text("key ${device.keyId}", style = MaterialTheme.typography.bodySmall)
                }
                TextButton(onClick = { onShowDeviceQr(device) }) { Text("Show QR") }
                TextButton(onClick = { onRemoveDevice(device.keyId) }) { Text("Remove") }
            }
        }
        Text(
            "\"Show QR\" re-displays a pairing record (e.g. after losing the " +
                "Chromebook's browser profile: scan it with the extension to restore).",
            style = MaterialTheme.typography.bodySmall
        )
        HorizontalDivider()

        Text("Autofill", style = MaterialTheme.typography.titleSmall)
        Button(onClick = onEnableAutofill, modifier = Modifier.fillMaxWidth()) {
            Text(if (autofillEnabled) "Autofill: enabled (re-open settings)" else "Enable autofill service")
        }
        HorizontalDivider()
        Text("Idle lock and encryption at rest", style = MaterialTheme.typography.titleSmall)
        // THE TWO CONCERNS SPLIT: the entry gate (the biometric/PIN before
        // the key at unlock) and the idle auto-lock (zeroing the session
        // after N idle seconds) are independent — the idle lock's re-entry
        // path (the card/seal gates) exists regardless.
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                "Enable idle lock?",
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodySmall
            )
            Switch(checked = idleLockOn, onCheckedChange = { onIdleLockToggle(it) })
        }
        if (idleLockOn) {
            var autoLockInput by remember(autoLockSeconds) {
                mutableStateOf(autoLockSeconds.toString())
            }
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = autoLockInput,
                    onValueChange = { text ->
                        autoLockInput = text.filter { it.isDigit() }.take(4)
                        autoLockInput.toIntOrNull()?.let { onAutoLockChange(it) }
                    },
                    label = { Text("Auto-lock (idle seconds; 0 = never)") },
                    singleLine = true,
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.Number),
                    modifier = Modifier.weight(1f)
                )
            }
            Text(
                "After this many idle seconds the decrypted session is zeroed " +
                    "(everything back to encrypted at rest). Applies to app use " +
                    "and backgrounding alike.",
                style = MaterialTheme.typography.bodySmall
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                "Require screenlock (biometric/PIN) at unlock",
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodySmall
            )
            Switch(checked = screenLockOn, onCheckedChange = { onScreenLockToggle(it) })
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                "Encrypt items in memory — " +
                    "search/list works sealed; clicking an entry reveals it " +
                    "with a screen-lock prompt.",
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodySmall
            )
            Switch(
                checked = screenlockUnlockOn,
                onCheckedChange = { onScreenlockUnlockToggle(it) })
        }
        Button(onClick = onLock, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Lock vault (zero decrypted data)")
        }
        HorizontalDivider()

        HorizontalDivider()
        // The OpenKeyChain seeding: the repo's materialized recipient keys
        // get imported into OKK so decrypt/encrypt work without a manual
        // per-key import on this phone.
        Text("OpenKeyChain export", style = MaterialTheme.typography.titleSmall)
        Button(onClick = onInitOkkFromRepo,
            enabled = busy == null,
            modifier = Modifier.fillMaxWidth()
        ) { Text("Initialize OpenKeyChain from this repo's keys") }
        HorizontalDivider()

        // Starting over: the app holds the decrypted state only in memory
        // and the encrypted state in its files — clearing the app's data
        // (or reinstalling) returns to the first-run screen, where the
        // backup imports cleanly (a restore without a repo adopts the
        // file's recipients).
        Text("Start over", style = MaterialTheme.typography.titleSmall)
        Text(
            "1. Back up first: Backups → USB → Export.\n" +
                "2. Clear the app's data: Android Settings → Apps → offlinepass → " +
                "Clear data.\n" +
                "3. Reopen: the first-run screen appears — Load existing → " +
                "Share vault → USB → Import (or scan the QRFT) and unlock.",
            style = MaterialTheme.typography.bodySmall
        )

        HorizontalDivider()

        if (busy != null) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        HorizontalDivider()
        Text("Log", style = MaterialTheme.typography.titleSmall)
        if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodyMedium)
    }
}
