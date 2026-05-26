const authToken = req.headers.authorization
const secretToken = req.body.token

// ruleid: js.security.timing-unsafe-secret-compare
if (authToken !== secretToken) {
  throw new Error("token mismatch")
}

// ok: js.security.timing-unsafe-secret-compare
if (crypto.timingSafeEqual(Buffer.from(authToken), Buffer.from(secretToken))) {
  allow()
}

function decrypt(data) {
  // ruleid: js.security.insecure-crypto-fallback
  return Buffer.from(data, "base64").toString()
}

function decryptSafely(data) {
  // ok: js.security.insecure-crypto-fallback
  return aesGcmDecrypt(data)
}

// ruleid: js.security.prisma-missing-ownership
const project = prisma.project.findUnique({ where: { id: projectId } })

// ok: js.security.prisma-missing-ownership
const ownedProject = prisma.project.findUnique({ where: { id: projectId, userId: session.user.id } })

// ruleid: js.security.plaintext-token-storage
await prisma.verificationToken.create({ data: { token: resetToken } })

// ok: js.security.plaintext-token-storage
await prisma.verificationToken.create({ data: { token: hashToken(resetToken) } })

// ruleid: js.security.auth-endpoint-no-ratelimit
app.post("/login", function loginHandler(req, res) {
  return res.json({ ok: true })
})

// ok: js.security.auth-endpoint-no-ratelimit
app.post("/signin", rateLimit(), function safeLoginHandler(req, res) {
  return res.json({ ok: true })
})
