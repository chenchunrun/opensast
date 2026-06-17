// Kotlin security rule test fixtures

import android.content.Context
import android.webkit.WebView
import java.io.File
import java.security.SecureRandom
import kotlinx.coroutines.*
import kotlin.random.Random

class KotlinSecurityTest {

    // --- SQL Injection ---
    fun testSqlInjection(userInput: String, conn: java.sql.Connection) {
        // ruleid: kotlin.security.sql-injection-string-concat
        conn.execute("SELECT * FROM users WHERE name='" + userInput + "'")

        // ok: kotlin.security.sql-injection-string-concat
        val stmt = conn.prepareStatement("SELECT * FROM users WHERE name=?")
        stmt.setString(1, userInput)
        stmt.execute()
    }

    // --- Command Injection ---
    fun testCommandInjection(host: String) {
        // ruleid: kotlin.security.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + host)

        // ok: kotlin.security.command-injection
        ProcessBuilder("ping", "-c", "1", "localhost").start()
    }

    // --- Insecure WebView ---
    fun testInsecureWebView(webView: WebView) {
        // ruleid: kotlin.security.insecure-webview
        webView.settings.javaScriptEnabled = true

        // ok: kotlin.security.insecure-webview
        webView.settings.javaScriptEnabled = true
        webView.settings.setSafeBrowsingEnabled(true)
    }

    // --- Hardcoded Credentials ---
    fun testHardcodedCredentials() {
        // ruleid: kotlin.security.hardcoded-credentials
        val apiKey = "sk-live-1234567890abcdef"

        // ruleid: kotlin.security.hardcoded-credentials
        const val PASSWORD = "admin123"

        // ok: kotlin.security.hardcoded-credentials
        val apiKeyFromEnv = System.getenv("API_KEY")
    }

    // --- Insecure Random ---
    fun testInsecureRandom() {
        // ruleid: kotlin.security.insecure-random
        val rng = Random(42)

        // ruleid: kotlin.security.insecure-random
        val rng2 = java.util.Random()

        // ok: kotlin.security.insecure-random
        val secureRng = SecureRandom()
    }

    // --- Coroutine Context Leak ---
    fun testCoroutineLeak() {
        // ruleid: kotlin.security.coroutine-context-leak
        GlobalScope.launch {
            processSensitiveData()
        }

        // ok: kotlin.security.coroutine-context-leak
        CoroutineScope(Dispatchers.IO).launch {
            processSensitiveData()
        }
    }

    // --- Path Traversal ---
    fun testPathTraversal(userFile: String) {
        // ruleid: kotlin.security.path-traversal
        File(userFile).readText()

        // ok: kotlin.security.path-traversal
        File("/data/app/config.yml").readText()
    }

    private fun processSensitiveData() { /* ... */ }
}
