package com.linuxpass.app.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.linuxpass.app.vault.VaultSession

/**
 * The persistent Setup tab (user_flows.md): sync/remote config, identities,
 * USB save/restore, autofill enablement, vault export (qrft) entry point.
 */
@Composable
fun SetupTabScreen(
    status: String,
    busy: String?,
    onBack: () -> Unit,
    onTestSync: () -> Unit,
    onUsbSave: () -> Unit,
    onUsbRestore: () -> Unit,
    onEnableAutofill: () -> Unit,
    onForget: () -> Unit,
    patSave: (String) -> Unit,
    autofillEnabled: Boolean
) {
    val cfg = VaultSession.config()
    var patInput by remember { mutableStateOf("") }
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("← Back") }
            Text("Setup", style = MaterialTheme.typography.titleLarge)
        }
        Text("Remote: ${cfg?.remoteUrl ?: "(none — local-only)"}")
        Text("Recipients: ${cfg?.recipientEmails?.joinToString(", ") ?: "-"}")
        Text("Device: ${cfg?.deviceId?.take(8) ?: "-"}   Rev: ${VaultSession.currentRev()}")
        HorizontalDivider()
        Button(onClick = onTestSync, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Sync now (fetch/push)")
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
        Text("Autofill", style = MaterialTheme.typography.titleSmall)
        Button(onClick = onEnableAutofill, modifier = Modifier.fillMaxWidth()) {
            Text(if (autofillEnabled) "Autofill: enabled (re-open settings)" else "Enable autofill service")
        }
        HorizontalDivider()
        Text("PAT rotation (stored encrypted)", style = MaterialTheme.typography.titleSmall)
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
        Button(onClick = onForget, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
            Text("Forget config (keeps files)")
        }
        if (busy != null) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodyMedium)
    }
}
