package com.linuxpass.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.linuxpass.app.vault.DeviceRecord
import com.linuxpass.app.vault.ProtonItem

/**
 * Entry picker for the multi-entry QRFT export (Settings flow): select the
 * entries to export (Select all supported), then Export hands the selected
 * items back — the payload is a JSON array of Proton item objects, which
 * the receiving app's Import-from-QRFT parses and dedupes.
 */
@Composable
fun ExportPickScreen(
    items: List<ProtonItem>,
    onBack: () -> Unit,
    onExport: (List<ProtonItem>) -> Unit
) {
    val selected = remember { mutableStateMapOf<String, Boolean>() }
    // Select-all starts OFF so an accidental full export (plaintext on
    // screen) is a deliberate action, not a two-tap accident.
    val picked = items.filter { selected[it.itemUuid] == true }
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("← Back") }
            Text("Export as QRFT", style = MaterialTheme.typography.titleLarge)
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                if (picked.isEmpty()) "Nothing selected (${items.size} entries)"
                else "${picked.size} of ${items.size} selected",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.weight(1f)
            )
            TextButton(onClick = { items.forEach { selected[it.itemUuid] = true } }) { Text("Select all") }
            TextButton(onClick = { selected.clear() }, enabled = selected.isNotEmpty()) { Text("Clear") }
        }
        LazyColumn(modifier = Modifier.weight(1f)) {
            items(items, key = { it.itemUuid }) { item ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { selected[item.itemUuid] = !(selected[item.itemUuid] == true) },
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Checkbox(
                        checked = selected[item.itemUuid] == true,
                        onCheckedChange = { checked -> selected[item.itemUuid] = checked }
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(item.displayName)
                        Text(
                            item.identity.ifBlank { "(no identity)" },
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
                HorizontalDivider()
            }
        }
        Button(
            onClick = { onExport(picked) },
            enabled = picked.isNotEmpty(),
            modifier = Modifier.fillMaxWidth()
        ) { Text("Export ${if (picked.size == 1) "1 entry" else "${picked.size} entries"} as QRFT") }
    }
}

/**
 * Second export step (Plan 2 rev 2): a checklist of paired paste devices,
 * ALL PRE-SELECTED by default (redundancy matches the vault's multi-key
 * model) — the paste is encrypted once and each selected key can open it.
 * "No device (plain QRFT)" keeps the legacy readable-by-anyone export.
 * With no devices paired this screen never shows.
 */
@Composable
fun ExportTargetPickScreen(
    count: Int,
    devices: List<DeviceRecord>,
    onBack: () -> Unit,
    onExport: (List<DeviceRecord>?) -> Unit
) {
    val selected = remember(devices) {
        mutableStateMapOf<String, Boolean>().apply { devices.forEach { put(it.keyId, true) } }
    }
    val picked = devices.filter { selected[it.keyId] == true }
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("← Back") }
            Text("Paste targets", style = MaterialTheme.typography.titleLarge)
        }
        Text(
            "$count entr${if (count == 1) "y" else "ies"} selected. Encrypted pastes " +
                "open with ANY selected key (touch required).",
            style = MaterialTheme.typography.bodySmall
        )
        LazyColumn(modifier = Modifier.weight(1f).padding(top = 8.dp)) {
            items(devices, key = { it.keyId }) { device ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { selected[device.keyId] = !(selected[device.keyId] == true) },
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Checkbox(
                        checked = selected[device.keyId] == true,
                        onCheckedChange = { checked -> selected[device.keyId] = checked }
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(device.name)
                        Text("key ${device.keyId}", style = MaterialTheme.typography.bodySmall)
                    }
                }
                HorizontalDivider()
            }
        }
        Button(
            onClick = { onExport(picked) },
            enabled = picked.isNotEmpty(),
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(if (picked.size == 1) "Encrypt to ${picked[0].name}"
                 else "Encrypt to ${picked.size} keys (any one opens it)")
        }
        TextButton(
            onClick = { onExport(null) },
            modifier = Modifier.fillMaxWidth()
        ) { Text("No device (plain QRFT — anyone scanning can read it)") }
    }
}
