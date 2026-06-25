// ruleid: js.security.bcrypt-low-cost
hash(password, 10)

// ok: js.security.bcrypt-low-cost
hash(password, 12)

function decrypt(data) {
  // ruleid: js.security.legacy-decrypt-bypass
  return Buffer.from(data, 'base64').toString('utf-8')
}

function decryptSafely(data) {
  // ok: js.security.legacy-decrypt-bypass
  return decryptWithGcm(data)
}

// ruleid: js.session.no-maxage
const authOptions = { session: { strategy: "jwt" } }

// ok: js.session.no-maxage
const safeAuthOptions = { session: { strategy: "jwt", maxAge: 60 * 60 } }

// ruleid: js.security.weak-hash-md5
crypto.createHash("md5")

// ok: js.security.weak-hash-md5
crypto.createHash("sha256")

// ruleid: js.security.insecure-ssl-reject
const agent = { rejectUnauthorized: false }

// ok: js.security.insecure-ssl-reject
const safeAgent = { rejectUnauthorized: true }

// ruleid: js.security.hardcoded-iv
const IV = Buffer.from("0123456789abcdef")

// ok: js.security.hardcoded-iv
const safeIv = crypto.randomBytes(16)

// ruleid: js.security.hardcoded-iv
let iv = "0123456789abcdef0123456789abcdef"

// empty/short strings are not IV material
// ok: js.security.hardcoded-iv
let body = ''
// empty/short strings are not IV material
// ok: js.security.hardcoded-iv
let fullHtml = ''
// empty/short strings are not IV material
// ok: js.security.hardcoded-iv
let sseBuffer = ''

// ruleid: js.security.ecb-mode
crypto.createCipheriv("aes-128-ecb", key, null)

// ok: js.security.ecb-mode
crypto.createCipheriv("aes-256-gcm", key, iv)

// ruleid: js.security.console-log-sensitive
console.log(session.token)

// ok: js.security.console-log-sensitive
console.log("request complete")

// ruleid: js.security.express-session-memory
new MemoryStore()

// ok: js.security.express-session-memory
new RedisStore()

// ruleid: js.security.jwt-verify-none
jwt.decode(token)

// ok: js.security.jwt-verify-none
jwt.verify(token, secret)
