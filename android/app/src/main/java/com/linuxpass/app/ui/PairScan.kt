package com.linuxpass.app.ui

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
 * Pair-paste-device scanner: a WebView camera page (jsQR only — no QRFT
 * framing) that decodes the Chrome extension's single pairing QR and hands
 * the record JSON to the app via [Bridge]. CAMERA permission must be
 * granted before this screen opens (runtime check lives in MainActivity).
 */
@Composable
fun PairScanScreen(
    onRecord: (String) -> Unit,
    onBack: () -> Unit
) {
    Column(modifier = Modifier.fillMaxSize()) {
        Row(modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
            verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("← Stop") }
            Text("Point the camera at the extension's pairing QR",
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
                        override fun onPermissionRequest(request: android.webkit.PermissionRequest) {
                            request.grant(request.resources)
                        }
                    }
                    addJavascriptInterface(PairBridge(onRecord), "LinuxpassBridge")
                    loadUrl("https://appassets.androidplatform.net/assets/qrft/pairscan.html")
                }
            }
        )
    }
}

/** JS bridge: pairscan.html calls onPairRecord(text) with the record JSON.
 *  Arrives on a WebView thread; the app-side handler hops to main. */
private class PairBridge(handler: (String) -> Unit) {
    private val handlerRef = handler

    @JavascriptInterface
    fun onPairRecord(text: String) {
        handlerRef(text)
    }
}
