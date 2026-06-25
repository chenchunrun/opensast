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
