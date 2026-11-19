package com.offlinepass.autofilltest

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

/**
 * THE AUTOFILL TEST HARNESS: minimal login forms with the standard
 * autofill hints — the whole offlinepass autofill loop (the sheet, the
 * chips, the auth, the fill, the save request) drives against THIS,
 * natively and offline. The form modes (the intent extra "form"):
 * - **login** (default): the username + the password.
 * - **signup**: the username + the password + the CONFIRM password (the
 *   generate-fill must land the same value in both).
 * - **nohints**: the password detected ONLY by its inputType (the
 *   heuristics' last fallback — no hints, no id substrings).
 * The submit = finish() — the framework's save-request fires on the
 * activity's finish with the changed fields (the save-offer's trigger).
 */
class LoginTestActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val form = intent.getStringExtra("form") ?: "login"
        title = "Autofill test: $form"

        fun field(hint: String, password: Boolean, hints: Boolean = true): EditText =
            EditText(this).apply {
                this.hint = hint
                if (hints) {
                    setAutofillHints(
                        if (password) View.AUTOFILL_HINT_PASSWORD
                        else View.AUTOFILL_HINT_USERNAME)
                }
                inputType = if (password) android.text.InputType.TYPE_CLASS_TEXT or
                    android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
                else android.text.InputType.TYPE_CLASS_TEXT
            }

        val fields = mutableListOf<Pair<String, EditText>>()
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 96, 48, 48)
        }
        col.addView(TextView(this).apply { text = "form: $form" })

        when (form) {
            "signup" -> {
                fields += "username" to field("Username", false)
                fields += "password" to field("Password", true)
                fields += "confirm" to field("Confirm password", true)
            }
            "nohints" -> {
                // The username = NOT hinted (the typed-only case); the
                // password = the inputType only — the heuristics must
                // still classify both.
                fields += "username" to field("Username (no hints)", false, hints = false)
                fields += "password" to field("Password (inputType only)", true, hints = false)
            }
            else -> {
                fields += "username" to field("Username", false)
                fields += "password" to field("Password", true)
            }
        }
        fields.forEach { col.addView(it.second) }

        col.addView(Button(this).apply {
            text = "Log In (finish → save request)"
            setOnClickListener {
                val captured = fields.joinToString(" ") { (name, f) ->
                    "$name=[${f.text}]"
                }
                Log.i(TAG, "SUBMIT $form: $captured")
                Toast.makeText(
                    this@LoginTestActivity, "captured: $captured",
                    Toast.LENGTH_LONG).show()
                // THE FINISH = the save-request's trigger: the framework
                // diffs the initial vs the final structure.
                finish()
            }
        })
        col.addView(Button(this).apply {
            text = "Clear fields"
            setOnClickListener { fields.forEach { (_, f) -> f.setText("") } }
        })
        setContentView(col)
    }

    companion object {
        private const val TAG = "AutofillTest"
    }
}
