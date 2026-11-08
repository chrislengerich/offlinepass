package com.linuxpass.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.linuxpass.app.vault.VaultSession

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
    onRemoveRecipient: (Long) -> Unit,
    signerLabel: String,
    onPickSigner: () -> Unit,
    onClearSigner: () -> Unit,
    screenLockOn: Boolean,
    onScreenLockToggle: (Boolean) -> Unit,
    onLock: () -> Unit,
    onExportQrft: () -> Unit,
    onImportQrft: () -> Unit,
    onPairDevice: () -> Unit = {},
    pairedDevices: List<com.linuxpass.app.vault.DeviceRecord> = emptyList(),
    onShowDeviceQr: (com.linuxpass.app.vault.DeviceRecord) -> Unit = {},
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

        // Sync state lives directly with its button.
        if (cfg?.remoteUrl != null) {
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

        Text("Recipients (from OpenKeyChain picker)", style = MaterialTheme.typography.titleSmall)
        if (recipientIds.isEmpty()) {
            Text("(none — add one before saving)", style = MaterialTheme.typography.bodySmall)
        }
        recipientIds.forEach { id ->
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                Text("0x%016X".format(id), modifier = Modifier.weight(1f))
                TextButton(onClick = { onRemoveRecipient(id) }) { Text("Remove") }
            }
        }
        Button(onClick = onAddRecipient, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Add recipient (pick in OpenKeyChain)")
        }
        HorizontalDivider()
        Text("Commit signer", style = MaterialTheme.typography.titleSmall)
        Text("Signer: $signerLabel", style = MaterialTheme.typography.bodySmall)
        Button(onClick = onPickSigner, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Pick signing key (OpenKeyChain)")
        }
        TextButton(onClick = onClearSigner, enabled = VaultSession.signingKeyId() != null) {
            Text("Use default (first recipient)")
        }
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
        Button(onClick = onExportQrft, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Export as QRFT (pick entries)")
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
