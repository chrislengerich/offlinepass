package com.offlinepass.app.spike

import android.app.Activity
import android.os.Bundle
import com.offlinepass.app.R

/**
 * A fake login form so the autofill service can be exercised on-device
 * (S4): XML EditTexts with idEntry "username"/"password" + autofillHints —
 * exactly the shape the field heuristics match.
 */
class FakeLoginActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.fake_login)
    }
}
