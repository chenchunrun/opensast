const userInput = req.body.payload
const secretToken = req.headers["x-token"]
const providedToken = req.body.token

// ruleid: javascript.security.timing-attack
if (secretToken !== providedToken) {
  deny()
}

// ok: javascript.security.timing-attack
if (crypto.timingSafeEqual(Buffer.from(secretToken), Buffer.from(providedToken))) {
  allow()
}

// Plain identifier holding a secret compared for equality -> flagged.
// ruleid: javascript.security.timing-attack
if (hmac === expectedHmac) {
  deny()
}

// --- Field-regression false positives (KoKoApp scan 2026-10-31) ---

// typeof guards are not secret comparisons.
// ok: javascript.security.timing-attack
if (typeof token !== "string") { deny() }

// Null/undefined checks are not secret comparisons.
// ok: javascript.security.timing-attack
if (token === null) { deny() }
// ok: javascript.security.timing-attack
if (accessToken !== undefined) { allow() }

// Length checks leak nothing about the secret value.
// ok: javascript.security.timing-attack
if (reqToken.length === 32) { allow() }

// Property accesses (status enums) are not the secret itself.
// ok: javascript.security.timing-attack
if (review.secretStatus !== "recovered") { deny() }

// Role/status literals are not secret material.
// ok: javascript.security.timing-attack
if (user.role === "admin") { allow() }

// Function-shape probes are not secret comparisons.
// ok: javascript.security.timing-attack
if (typeof authorize === "function") { allow() }


// ruleid: javascript.security.eval-usage
eval(userInput)

// ok: javascript.security.eval-usage
eval("2 + 2")

// function-arg timer is not eval
// ok: javascript.security.eval-usage
setTimeout(() => controller.abort(), 1000)
// function-arg timer is not eval
// ok: javascript.security.eval-usage
setInterval(() => poll(), 5000)

// ruleid: javascript.security.deserialize-unsafe
serialize.unserialize(userInput)

// literal arg, not user input
// ok: javascript.security.deserialize-unsafe
serialize.unserialize("{}")

// JSON.parse is not code execution
// ok: javascript.security.deserialize-unsafe
JSON.parse(userInput)

// ruleid: javascript.security.nosql-injection-mongo
db.users.find({$where: userInput})

// ok: javascript.security.nosql-injection-mongo
db.users.find({$where: "this.enabled === true"})

// ruleid: javascript.security.hardcoded-secret-string
const apiToken = "prod-token-value"

// ok: javascript.security.hardcoded-secret-string
const apiTokenFromEnv = process.env.API_TOKEN
