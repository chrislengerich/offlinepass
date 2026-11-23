package com.offlinepass.app.ui

import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebView
import androidx.webkit.WebViewAssetLoader
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.webkit.WebViewClientCompat

/**
 * Import-from-QRFT receiver: a WebView camera scanner running the vendored
 * qrft scanner page (jsQR + pako) at a secure origin. The page decodes the
 * sender's looping QR frames, reassembles the payload, and hands it back
 * through a JS bridge ([Bridge]). CAMERA permission must be granted before
 * this screen opens (the runtime check lives in MainActivity).
 */
@Composable
fun QrftScanScreen(
    onPayload: (name: String, payload: String) -> Unit,
    onBack: () -> Unit,
    /** THE RAW MODE (the TOTP QR): every decoded QR is handed to the app
     *  as-is — no QRFT frame reassembly. */
    rawMode: Boolean = false,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        Row(modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
            verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("← Stop") }
            Text(
                if (rawMode) "Point the camera at the TOTP QR code"
                else "Point the camera at the sending phone's looping QR",
                style = MaterialTheme.typography.bodySmall)
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
                    settings.mediaPlaybackRequiresUserGesture = false
                    webViewClient = object : WebViewClientCompat() {
                        override fun shouldInterceptRequest(
                            view: WebView,
                            request: android.webkit.WebResourceRequest
                        ): android.webkit.WebResourceResponse? =
                            assetLoader.shouldInterceptRequest(request.url)
                    }
                    webChromeClient = object : WebChromeClient() {
                        // getUserMedia on the secure appassets origin: grant
                        // the camera (the app-level CAMERA permission was
                        // requested before this screen opened).
                        override fun onPermissionRequest(request: android.webkit.PermissionRequest) {
                            request.grant(request.resources)
                        }
                    }
                    addJavascriptInterface(Bridge(onPayload), "OfflinepassBridge")
                    loadUrl(
                        "https://appassets.androidplatform.net/assets/qrft/scanner.html" +
                            if (rawMode) "?mode=raw" else ""
                    )
                }
            }
        )
    }
}

/** JS bridge: the scanner page calls onPayload(name, text) when the
 * transfer completes. The call arrives on a WebView thread; the app-side
 * handler must hop to the main dispatcher itself. */
private class Bridge(handler: (String, String) -> Unit) {
    private val handlerRef = handler

    @JavascriptInterface
    fun onPayload(name: String, payload: String) {
        handlerRef(name, payload)
    }
}
