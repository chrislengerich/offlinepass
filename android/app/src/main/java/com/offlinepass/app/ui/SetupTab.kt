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
    onUsbSave: () -> Unit,
    onUsbRestore: () -> Unit,
    onEnableAutofill: () -> Unit,
    onForget: () -> Unit,
    patSave: (String) -> Unit,
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
    onUseOpenKeyChain: () -> Unit = {},
    screenLockOn: Boolean,
    onScreenLockToggle: (Boolean) -> Unit,
    autoLockMinutes: Int = 5,
    onAutoLockChange: (Int) -> Unit = {},
    screenlockUnlockOn: Boolean = false,
    onScreenlockUnlockToggle: (Boolean) -> Unit = {},
    onLock: () -> Unit,
    onExportQrft: () -> Unit,
    onExportBackupZip: () -> Unit = {},
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
    onSshSelfTest: () -> Unit = {},
    onRemoveDevice: (String) -> Unit = {}
) {
    val cfg = VaultSession.config()
    var patInput by remember { mutableStateOf("") }
    var confirmDialog by remember { mutableStateOf<String?>(null) }

    confirmDialog?.let { what ->
        AlertDialog(
            onDismissRequest = { confirmDialog = null },
            title = { Text("Confirm reset") },
            text = {
                Text(
                    if (what == "repo") "Wipe the local git clone and re-clone from the remote? "
                        + "Unpushed work is re-applied automatically if the vault is unlocked."
                    else "Forget the configuration? The vault files stay on the device; "
                        + "you'll return to the setup screen."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val action = confirmDialog
                    confirmDialog = null
                    if (action == "repo") onResetRepo() else onForget()
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
        Text("Device: ${cfg?.deviceId?.take(8) ?: "-"}   Rev: ${VaultSession.currentRev()}")

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
        // The SSH-auth slot: the SIG (the default) vs the AUT (the
        // dedicated authentication key — the transport experiment). The
        // same pref the commit-signer's cardSign reads.
        androidx.compose.material3.ListItem(
            headlineContent = { Text("SSH auth subkey: use the AUT key") },
            supportingContent = { Text("Off = the SIG signing subkey answers " +
                "the SSH handshake (the card pads the digest). On = the AUT " +
                "authentication subkey (the raw-RSA challenge, the caller " +
                "pads — the 512-byte transport experiment).") },
            trailingContent = {
                androidx.compose.material3.Switch(
                    checked = VaultSession.sshAuthUseAut(),
                    onCheckedChange = { VaultSession.setSshAuthUseAut(it) })
            })

        // Sync state lives directly with its button.
        // The commit summaries = the LOCAL-ONLY too (the git history = on-device).
        val commits = VaultSession.recentCommits()
        if (commits.isNotEmpty()) {
            Text(
                if (cfg?.remoteUrl != null) "Sync: ${VaultSession.syncStatus ?: "not synced this session"}"
                else "Local-only vault (no remote attached)",
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

        Text("Recipients (from the vault ledger; adds use OpenKeyChain)", style = MaterialTheme.typography.titleSmall)
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
        Text("This device", style = MaterialTheme.typography.titleSmall)
        var deviceNameInput by androidx.compose.runtime.remember {
            androidx.compose.runtime.mutableStateOf(VaultSession.deviceName())
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            androidx.compose.material3.OutlinedTextField(
                value = deviceNameInput, onValueChange = { deviceNameInput = it },
                label = { Text("Device name") }, singleLine = true,
                modifier = Modifier.weight(1f))
            Button(onClick = { onSetDeviceName(deviceNameInput) }, enabled = busy == null) {
                Text("Set")
            }
        }
        Button(
            onClick = onInitOkkFromRepo,
            enabled = busy == null,
            modifier = Modifier.fillMaxWidth()
        ) { Text("Initialize OpenKeyChain from this repo's keys") }
        HorizontalDivider()
        if (cfg?.remoteUrl != null) {
            Text("Devices", style = MaterialTheme.typography.titleSmall)
            val devices = VaultSession.deviceListLabels()
            if (devices.isEmpty()) {
                Text("(no devices registered yet — the first sync adds this device)",
                    style = MaterialTheme.typography.bodySmall)
            } else {
                devices.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
        }
        Text("Commit signer", style = MaterialTheme.typography.titleSmall)
        if (VaultSession.commitSigningMode() == VaultSession.SIGNING_SCREENLOCK) {
            // Screenlock mode: OpenKeyChain signing is not used at all.
            Text(
                "Screen lock (keystore key " +
                    com.offlinepass.app.crypto.KeystoreSigner.publicKeyFingerprint() + ") — " +
                    "every save prompts for the screen lock; OpenKeyChain is not involved.",
                style = MaterialTheme.typography.bodySmall
            )
            Button(
                onClick = onUseOpenKeyChain,
                enabled = busy == null,
                modifier = Modifier.fillMaxWidth()
            ) { Text("Switch to OpenKeyChain signing") }
            if (VaultSession.yubikeyAuthSubkeyId() != null) {
                Button(
                    onClick = onUseYubikeySigner,
                    enabled = busy == null,
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Use the YubiKey (touch to sign)") }
            }
            TextButton(
                onClick = onRemoveScreenlock,
                enabled = busy == null,
                modifier = Modifier.fillMaxWidth()
            ) { Text("Remove screenlock signing (migrate to the security key)") }
        } else if (VaultSession.commitSigningMode() == VaultSession.SIGNING_YUBIKEY) {
            Text(
                "YubiKey (SIG slot subkey 0x" +
                    (VaultSession.yubikeyAuthSubkeyId()
                        ?.let { "%016X".format(it) } ?: "?") +
                    ") — every save prompts for the OpenPGP PIN and the touch.",
                style = MaterialTheme.typography.bodySmall
            )
            Button(
                onClick = onPickSigner,
                enabled = busy == null,
                modifier = Modifier.fillMaxWidth()
            ) { Text("Switch to OpenKeyChain signing") }
            Button(
                onClick = onEnrollScreenlock,
                enabled = busy == null && deviceCredentialReady,
                modifier = Modifier.fillMaxWidth()
            ) { Text("Enroll screenlock signing (alternative)") }
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
            TextButton(onClick = onRemoveYubikeySsh, enabled = busy == null) {
                Text("Remove")
            }
        } else {
            Text("YubiKey SSH: not enrolled.", style = MaterialTheme.typography.bodySmall)
        }
        Text("Active mode: " + VaultSession.sshSyncMode(), style = MaterialTheme.typography.bodySmall)
        HorizontalDivider()

        Text("USB offline copies", style = MaterialTheme.typography.titleSmall)
        Button(onClick = onUsbSave, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Save vault snapshot to USB/file")
        }
        Button(onClick = onUsbRestore, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Restore vault from USB/file (merge)")
        }
        HorizontalDivider()

        Text("QRFT transfer (phone ↔ phone, via camera)", style = MaterialTheme.typography.titleSmall)
        // The USB export = the WHOLE REPO (the git-state clone: the vault +
        // the keys + the signed history) — the backup/restore. The QRFT =
        // the picked entries only (the transfer format).
        Button(onClick = onExportBackupZip, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Export whole repo (USB)")
        }
        Button(onClick = onExportQrft, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Export entries as QRFT")
        }
        Button(onClick = onImportQrft, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Import from QRFT (scan)")
        }
        Button(onClick = onPairDevice, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Pair paste device (scan extension QR)")
        }
        HorizontalDivider()

        Text("Paste devices (Chrome extension)", style = MaterialTheme.typography.titleSmall)
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
        Text("Screen lock (optional)", style = MaterialTheme.typography.titleSmall)
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                "Require biometric/PIN before the key on unlock",
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodySmall
            )
            Switch(checked = screenLockOn, onCheckedChange = { onScreenLockToggle(it) })
        }
        if (screenLockOn) {
            // The screenlock toggle now governs the idle auto-lock too:
            // after N minutes untouched, the decrypted session is zeroed —
            // everything is back to encrypted-at-rest. The timeout is a
            // free-form field (minutes; 0 = never).
            var autoLockInput by remember(autoLockMinutes) {
                mutableStateOf(autoLockMinutes.toString())
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
                    label = { Text("Auto-lock (idle minutes; 0 = never)") },
                    singleLine = true,
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.Number),
                    modifier = Modifier.weight(1f)
                )
            }
            Text(
                "After this many idle minutes the decrypted session is zeroed " +
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
                "Encrypt individual items while in use (experimental) — " +
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

        Text(
            "PAT: ${if (VaultSession.hasPat()) "stored (encrypted in Android Keystore)" else "not stored"}",
            style = MaterialTheme.typography.titleSmall
        )
        OutlinedTextField(
            value = patInput, onValueChange = { patInput = it },
            label = { Text("New fine-grained PAT") }, singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        Button(
            onClick = { if (patInput.isNotBlank()) patSave(patInput.trim()); patInput = "" },
            enabled = patInput.isNotBlank(),
            modifier = Modifier.fillMaxWidth()
        ) { Text("Save PAT") }
        HorizontalDivider()

        Button(onClick = { confirmDialog = "forget" }, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Forget config (keeps files)")
        }
        if (busy != null) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodyMedium)
    }
}
