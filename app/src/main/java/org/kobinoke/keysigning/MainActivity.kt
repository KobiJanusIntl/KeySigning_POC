package org.kobinoke.keysigning

import android.app.Activity
import android.content.res.Resources
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import org.json.JSONObject
import java.time.Instant

class MainActivity : AppCompatActivity() {

    private lateinit var keyManager: PhoneKeyManager
    private lateinit var resultText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val root = findViewById<View>(R.id.root_view)
        setInsets(root)

        keyManager = PhoneKeyManager(this)
        resultText = findViewById(R.id.result_text)

        val btnGenerateKey = findViewById<Button>(R.id.btn_generate_key)
        val btnSignAcl = findViewById<Button>(R.id.btn_sign_acl)
        val btnSignCommand = findViewById<Button>(R.id.btn_sign_command)

        btnGenerateKey.setOnClickListener {
            keyManager.ensureKeys()
            val pubKey = keyManager.getRawPublicKey()
            resultText.text = "Key ensured!\nPublic key (raw 32 bytes Base64):\n${Base64.encodeToString(pubKey, Base64.NO_WRAP)}"
        }

        btnSignAcl.setOnClickListener {
            val pubKey = keyManager.getRawPublicKey()
            val acl = PhoneKeyAcl(
                aclId = "acl-123",
                lockMac = "AA:BB:CC:DD:EE:FF",
                phoneKeyId = keyManager.getKeyId(),
                phonePublicKey = pubKey,
                issuedAt = Instant.now(),
                expiresAt = Instant.now().plusSeconds(3600),
                schedule = listOf(
                    PhoneKeyAcl.TimeWindow(
                        start = Instant.now(),
                        end = Instant.now().plusSeconds(1800)
                    )
                ),
                permissions = PhoneKeyAcl.Permissions(
                    unlock = true,
                    overrideOverlock = false,
                    configWrite = true,
                    fwUpdate = false
                ),
                meta = PhoneKeyAcl.Meta(
                    ttlHours = 1,
                    timeSource = "device",
                    hwType = "android"
                )
            )

            // Canonicalize ACL for signing
            val aclJson = JSONObject().apply {
                put("aclId", acl.aclId)
                put("lockMac", acl.lockMac)
                put("phoneKeyId", acl.phoneKeyId)
                put("phonePublicKey", Base64.encodeToString(acl.phonePublicKey, Base64.NO_WRAP))
                put("issuedAt", keyManager.iso8601String(acl.issuedAt))
                put("expiresAt", keyManager.iso8601String(acl.expiresAt))
            }

            val canonicalBytes = keyManager.canonicalizeJSON(aclJson).toString().toByteArray(Charsets.UTF_8)
            val signatureBytes = keyManager.sign(canonicalBytes)
            acl.signature = PhoneKeyAcl.Signature(
                algorithm = "Ed25519",
                value = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
            )

            resultText.text = "Signed ACL:\n$acl"
        }

        btnSignCommand.setOnClickListener {
            val cmd = keyManager.createCommand(
                type = "unlock",
                payload = mapOf("lockMac" to "AA:BB:CC:DD:EE:FF")
            )
            resultText.text = "Signed Command:\n$cmd"
        }
    }
}

fun Activity.makeSystemBarTransparent(isWhite: Boolean = true) {
    WindowCompat.setDecorFitsSystemWindows(window, false)

    window.statusBarColor = Color.TRANSPARENT
    window.navigationBarColor = Color.TRANSPARENT

    WindowInsetsControllerCompat(window, window.decorView).apply {
        isAppearanceLightStatusBars = isWhite
        isAppearanceLightNavigationBars = isWhite
    }
}

fun Activity.setInsets(rootView: View, isWhite: Boolean = true) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
        return
    }
    makeSystemBarTransparent(isWhite)
    ViewCompat.setOnApplyWindowInsetsListener(rootView) { view, insets ->
        val systemBarsInsets = insets.getInsets(WindowInsetsCompat.Type.systemBars())
        val extraTop = 30.dp
        view.setPadding(
            systemBarsInsets.left,
            systemBarsInsets.top + extraTop,
            systemBarsInsets.right,
            systemBarsInsets.bottom
        )
        WindowInsetsCompat.CONSUMED
    }
}

val Int.dp: Int get() = (this * Resources.getSystem().displayMetrics.density).toInt()
