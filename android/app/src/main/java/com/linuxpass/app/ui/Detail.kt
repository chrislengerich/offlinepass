package com.linuxpass.app.ui

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.linuxpass.app.vault.ProtonItem
import com.linuxpass.app.vault.Totp
import org.json.JSONObject

/** Compact Proton-JSON payload for one entry — the QR Autofill format. */
fun entryPayload(item: ProtonItem): String = item.toProtonJson().toString()

/** Renders a payload as a QR bitmap with ZXing (kept for qrft frame debugging). */
fun qrBitmap(payload: String, sizePx: Int = 700): Bitmap {
    val matrix = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, sizePx, sizePx)
    val bmp = Bitmap.createBitmap(matrix.width, matrix.height, Bitmap.Config.RGB_565)
    for (y in 0 until matrix.height) for (x in 0 until matrix.width) {
        bmp.setPixel(x, y, if (matrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
    }
    return bmp
}

/**
 * Entry detail: fields, reveal, live TOTP, and the entry options the TUI
 * offers — QR export via the vendored qrft generator, update password,
 * enroll TOTP, delete.
 */
@Composable
fun EntryDetailScreen(
    item: ProtonItem,
    status: String,
    busy: String?,
    onBack: () -> Unit,
    onExportQr: () -> Unit,
    onUpdatePassword: () -> Unit,
    onEnrollTotp: (String) -> Unit,
    onDelete: () -> Unit
) {
    var revealed by remember { mutableStateOf(false) }
    var totp by remember { mutableStateOf<Pair<String, Int>?>(null) }
    var showTotpEntry by remember { mutableStateOf(false) }
    var totpInput by remember { mutableStateOf("") }

    // Live TOTP refresh.
    if (item.totpUri.isNotBlank()) {
        LaunchedEffect(item.totpUri) {
            while (true) {
                totp = runCatching { Totp.generate(item.totpUri) }.getOrNull()
                kotlinx.coroutines.delay(1000)
            }
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("← Back") }
            Text(item.displayName, style = MaterialTheme.typography.titleLarge)
        }
        Text("Username: ${item.identity.ifBlank { "-" }}")
        Text("Email: ${item.email.ifBlank { "-" }}")
        Text("URLs: ${item.urls.joinToString(", ").ifBlank { "-" }}")
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Password: ${if (revealed) item.password else "•".repeat(item.password.length)}")
            TextButton(onClick = { revealed = !revealed }) { Text(if (revealed) "Hide" else "Reveal") }
        }
        if (totp != null) {
            val (code, remaining) = totp!!
            Text("TOTP: $code  (${remaining}s)", style = MaterialTheme.typography.titleMedium)
            LinearProgressIndicator(
                progress = { remaining.toFloat() / 30f },
                modifier = Modifier.fillMaxWidth()
            )
        }
        if (item.note.isNotBlank()) Text("Note: ${item.note}")

        HorizontalDivider()
        Button(onClick = onExportQr, modifier = Modifier.fillMaxWidth()) {
            Text("Export as QRFT")
        }
        Button(onClick = onUpdatePassword, modifier = Modifier.fillMaxWidth()) { Text("Update password") }
        if (item.totpUri.isBlank()) {
            Button(onClick = { showTotpEntry = true }, modifier = Modifier.fillMaxWidth()) {
                Text("Enroll TOTP")
            }
        } else {
            Text("TOTP enrolled", style = MaterialTheme.typography.bodySmall)
        }
        Button(onClick = onDelete, modifier = Modifier.fillMaxWidth()) {
            Text("Delete entry")
        }
        if (busy != null) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodyMedium)

        if (showTotpEntry) {
            OutlinedTextField(
                value = totpInput,
                onValueChange = { totpInput = it },
                label = { Text("Base32 secret or otpauth:// URI") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    onEnrollTotp(Totp.normalizeSecretInput(totpInput))
                    showTotpEntry = false
                }) { Text("Save") }
                OutlinedButton(onClick = { showTotpEntry = false }) { Text("Cancel") }
            }
        }
    }
}
