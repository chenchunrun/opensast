// Test corpus for JavaScript/TypeScript rules
// Lines with // ruleid: should trigger
// Lines with // ok: should NOT trigger

import { NextRequest, NextResponse } from "next/server";
import { exec, execSync } from "child_process";
import { z } from "zod";

// --- command-injection ---

// ruleid: javascript.security.command-injection-exec
exec(`ls ${userInput}`)

// ruleid: javascript.security.command-injection-exec
exec("ls " + userInput)

// ok: javascript.security.command-injection-exec
exec("ls -la")

// --- sql-injection ---

// ruleid: javascript.security.sql-injection-string-concat
db.query(`SELECT * FROM users WHERE id = ${userId}`)

// ruleid: javascript.security.sql-injection-string-concat
db.query("SELECT * FROM users WHERE id = " + userId)

// ok: javascript.security.sql-injection-string-concat
db.query("SELECT * FROM users WHERE id = ?", [userId])

// --- xss ---

// ruleid: javascript.security.xss-response-send
res.send(`<h1>${userName}</h1>`)

// ok: javascript.security.xss-response-send
res.send(escapeHtml(content))

// --- path-traversal ---

// ruleid: javascript.security.path-traversal
fs.readFile(`./data/${userInput}`)

// ok: javascript.security.path-traversal
path.join("data", "static")

// --- ssrf ---

// ruleid: javascript.security.ssrf-fetch
fetch(req.query.url)

// ok: javascript.security.ssrf-fetch
fetch("https://api.example.com/data")

// --- open-redirect ---

// ruleid: javascript.security.open-redirect
res.redirect(userInput)

// ok: javascript.security.open-redirect
res.redirect("/dashboard")

// --- timing-attack ---

// ruleid: javascript.security.timing-attack
if (token === userInput) { }

// --- hardcoded-secret ---

// ruleid: javascript.security.hardcoded-secret-default
process.env.SECRET_KEY || "default-secret"

// ok: javascript.security.hardcoded-secret-default
process.env.SECRET_KEY

// --- insecure-cors ---

// ruleid: javascript.security.insecure-cors
headers.set("Access-Control-Allow-Origin", req.headers.get("origin"))

// --- eval ---

// ruleid: javascript.security.eval-usage
eval(userCode)

// ok: javascript.security.eval-usage
eval("2 + 2")

// --- dom-xss ---

// ruleid: js.security.dom-xss-innerhtml
element.innerHTML = userInput

// ok: js.security.dom-xss-innerhtml
element.innerHTML = DOMPurify.sanitize(userInput)
