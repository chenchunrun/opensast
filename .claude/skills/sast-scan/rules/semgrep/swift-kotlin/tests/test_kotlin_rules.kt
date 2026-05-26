import android.content.Intent
import android.util.Log
import java.security.MessageDigest

data class User(val password: String, val token: String)

fun vulnerable(userAction: String, uri: android.net.Uri, user: User, password: String, token: String) {
    // ruleid: kotlin.security.hardcoded-credentials
    val password = "android-password"

    // ruleid: kotlin.security.hardcoded-credentials
    val apiKey = "android-api-key"

    // ok: kotlin.security.hardcoded-credentials
    val secretFromStore = loadSecret()

    // ruleid: kotlin.security.insecure-random
    java.util.Random()

    // ok: kotlin.security.insecure-random
    java.security.SecureRandom()

    // ruleid: kotlin.security.weak-hash-md5
    MessageDigest.getInstance("MD5")

    // ruleid: kotlin.security.weak-hash-md5
    MessageDigest.getInstance("SHA-1")

    // ok: kotlin.security.weak-hash-md5
    MessageDigest.getInstance("SHA-256")

    class TrustAllManager {
        // ruleid: kotlin.security.ssl-trust-all
        fun checkServerTrusted() {}

        // ruleid: kotlin.security.ssl-trust-all
        fun getAcceptedIssuers() = emptyArray<java.security.cert.X509Certificate>()
    }

    val manager = TrustAllManager()
    manager.hashCode()

    // ok: kotlin.security.ssl-trust-all
    validateServerCertificates()

    // ruleid: kotlin.security.intent-injection
    Intent(userAction)

    // ruleid: kotlin.security.intent-injection
    Intent(userAction, uri)

    // ok: kotlin.security.intent-injection
    Intent("com.example.SAFE_ACTION")

    // ruleid: kotlin.security.webview-js-enabled
    webView.settings.javaScriptEnabled = true

    // ok: kotlin.security.webview-js-enabled
    webView.settings.javaScriptEnabled = false

    // ruleid: kotlin.security.content-provider-exported
    exported = true

    // ok: kotlin.security.content-provider-exported
    exported = false

    // ruleid: kotlin.security.logging-sensitive
    Log.d("auth", user.password)

    // ruleid: kotlin.security.logging-sensitive
    Log.d("auth", token)

    // ok: kotlin.security.logging-sensitive
    Log.d("auth", "request complete")

    // ruleid: kotlin.security.shared-preference-plain
    MODE_WORLD_READABLE

    // ruleid: kotlin.security.shared-preference-plain
    MODE_WORLD_WRITEABLE

    // ok: kotlin.security.shared-preference-plain
    MODE_PRIVATE

    // ruleid: kotlin.security.sqlite-injection
    db.execSQL("DELETE FROM users WHERE name = '" + user.password + "'")

    // ruleid: kotlin.security.sqlite-injection
    db.rawQuery("SELECT * FROM users WHERE token = '" + token + "'", null)

    // ok: kotlin.security.sqlite-injection
    db.execSQL("DELETE FROM users WHERE id = ?", arrayOf(user.password))
}
