package com.offlinepass.autofilltest

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast

/**
 * THE AUTOFILL TEST HARNESS: a minimal login form with the standard
 * autofill hints — the whole offlinepass autofill loop (the sheet, the
 * chips, the auth, the fill, the save request) drives against THIS,
 * natively and offline: the views = uiautomator-readable (the field ids +
 * the values), the captured credentials surface in a toast + the log —
 * the proof of fill without touching the browser.
 */
class LoginTestActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "Autofill test login"

        val username = EditText(this).apply {
            hint = "Username"
            setAutofillHints(View.AUTOFILL_HINT_USERNAME)
            inputType = android.text.InputType.TYPE_CLASS_TEXT
        }
        val password = EditText(this).apply {
            hint = "Password"
            setAutofillHints(View.AUTOFILL_HINT_PASSWORD)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val login = Button(this).apply {
            text = "Log In (show captured)"
            setOnClickListener {
                val u = username.text.toString()
                val p = password.text.toString()
                Log.i(TAG, "captured: username=$u password=$p")
                Toast.makeText(
                    this@LoginTestActivity,
                    "captured: username=[$u] password=[${p.take(4)}…${p.takeLast(2)}]",
                    Toast.LENGTH_LONG).show()
            }
        }
        val reset = Button(this).apply {
            text = "Clear fields"
            setOnClickListener { username.setText(""); password.setText("") }
        }
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 96, 48, 48)
            addView(username)
            addView(password)
            addView(login)
            addView(reset)
        }
        setContentView(col)
    }

    companion object {
        private const val TAG = "AutofillTest"
    }
}
