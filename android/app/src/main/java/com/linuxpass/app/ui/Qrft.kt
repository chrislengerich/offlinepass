package com.linuxpass.app.ui

import android.content.Intent
import android.net.Uri
import android.webkit.*
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewClientCompat
import java.io.File

/**
 * S5 — the vendored qrft generator (airgap-qr-offline `generator.html` +
 * vendor libs) served from app assets at a secure origin, so the page's
 * camera-less QR loop runs fully offline. The payload file was written by
 * the app; the user picks it in the page's file chooser (SAF-bridged,
 * initial URI lands in the app's own dir).
 */
@Composable
fun QrftScreen(payloadFile: File, onBack: () -> Unit) {
    val context = LocalContext.current
    var fileCallback by remember { mutableStateOf<android.webkit.ValueCallback<Array<Uri>>?>(null) }

    val filePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        result.data?.data?.let { fileCallback?.onReceiveValue(arrayOf(it)) }
            ?: fileCallback?.onReceiveValue(null)
        fileCallback = null
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("← Back") }
            Text("qrft generator — pick entry-latest.json when prompted", style = MaterialTheme.typography.bodySmall)
        }
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { ctx ->
                val assetLoader = WebViewAssetLoader.Builder()
                    .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(ctx))
                    .build()
                WebView(ctx).apply {
                    settings.javaScriptEnabled = true
                    settings.domStorageEnabled = true
                    settings.allowFileAccess = false
                    webViewClient = object : WebViewClientCompat() {
                        override fun shouldInterceptRequest(
                            view: WebView,
                            request: WebResourceRequest
                        ): WebResourceResponse? = assetLoader.shouldInterceptRequest(request.url)
                    }
                    webChromeClient = object : WebChromeClient() {
                        override fun onShowFileChooser(
                            webView: WebView?,
                            cb: android.webkit.ValueCallback<Array<Uri>>,
                            params: FileChooserParams
                        ): Boolean {
                            fileCallback = cb
                            val intent = params.createIntent().apply {
                                addCategory(Intent.CATEGORY_OPENABLE)
                                putExtra(
                                    android.provider.DocumentsContract.EXTRA_INITIAL_URI,
                                    Uri.parse("content://com.android.externalstorage.documents/document/primary%3AAndroid%3Adata%3Acom.linuxpass.app%3Afiles")
                                )
                            }
                            filePicker.launch(intent)
                            return true
                        }
                    }
                    loadUrl("https://appassets.androidplatform.net/assets/qrft/generator.html")
                }
            },
            update = { }
        )
    }
}
