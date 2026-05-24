// Test corpus for Go rules
// Lines with // ruleid: should trigger
// Lines with // ok: should NOT trigger

package main

import (
    "database/sql"
    "fmt"
    "os"
    "os/exec"
    "crypto/tls"
    "net/http"
)

// --- sql-injection ---

// ruleid: go.security.sql-injection-string-concat
db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userId))

// ok: go.security.sql-injection-string-concat
db.Query("SELECT * FROM users WHERE id = $1", userId)

// --- command-injection ---

// ruleid: go.security.command-injection-exec
exec.Command("sh", "-c", userInput)

// ok: go.security.command-injection-exec
exec.Command("ls", "-la")

// --- ssrf ---

// ruleid: go.security.ssrf-http-get
client.Get(userUrl)

// ok: go.security.ssrf-http-get
client.Get("https://api.example.com")

// --- insecure-tls ---

// ruleid: go.security.insecure-tls-config
tls.Config{InsecureSkipVerify: true}

// --- path-traversal ---

// ruleid: go.security.path-traversal
os.Open(filepath.Join(base, userInput))

// ok: go.security.path-traversal
os.Open(filepath.Join("/data", "static"))

// --- weak-hash ---

// ruleid: go.security.weak-hash-md5
md5.Sum(data)

// ruleid: go.security.weak-hash-sha1
sha1.Sum(data)

// --- hardcoded-credentials ---

// ruleid: go.security.hardcoded-credentials
password := "supersecret123"

// ok: go.security.hardcoded-credentials
password := os.Getenv("DB_PASSWORD")
