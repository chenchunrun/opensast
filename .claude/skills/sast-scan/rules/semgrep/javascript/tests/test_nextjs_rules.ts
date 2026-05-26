import { cookies } from "next/headers"

// ruleid: nextjs.security.env-default-secret
const secret = process.env.NEXTAUTH_SECRET || "dev-secret"

// ok: nextjs.security.env-default-secret
const strictSecret = process.env.NEXTAUTH_SECRET

// ruleid: nextjs.security.insecure-cookie
cookies().set("session", token, { sameSite: "lax" })

// ok: nextjs.security.insecure-cookie
cookies().set("session", token, { httpOnly: true, secure: true, sameSite: "lax" })

// ruleid: nextjs.security.trust-host
const authConfig = { trustHost: true }

// ok: nextjs.security.trust-host
const safeAuthConfig = { trustHost: false }

// ruleid: nextjs.security.raw-query-unsafe
const users = prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = ${email}`)

// ok: nextjs.security.raw-query-unsafe
const safeUsers = prisma.$queryRawUnsafe("SELECT * FROM users WHERE email = ?", email)
