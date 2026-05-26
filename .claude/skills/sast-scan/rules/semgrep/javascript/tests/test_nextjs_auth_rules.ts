import { z } from "zod"

const schema = z.object({ name: z.string() })

// ruleid: nextjs.auth.missing-csrf-post
export async function POST(req: Request) {
  const body = await req.json()
  return Response.json(body)
}

// ok: nextjs.auth.missing-csrf-post
export async function DELETE(req: Request) {
  checkCsrf(req)
  return Response.json({ ok: true })
}

// ruleid: nextjs.validation.missing-zod-parse
export async function PUT(req: Request) {
  const body = await req.json()
  return Response.json(body)
}

// ok: nextjs.validation.missing-zod-parse
export async function PATCH(req: Request) {
  const body = await req.json()
  const parsed = schema.safeParse(body)
  return Response.json(parsed)
}

// ruleid: nextjs.validation.unsafe-type-assertion
const unsafeBody = body as Record<string, unknown>

// ok: nextjs.validation.unsafe-type-assertion
const validatedBody = schema.parse(body)

// ruleid: nextjs.security.query-raw-unsafe
const rows = prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${userId}`)

// ok: nextjs.security.query-raw-unsafe
const safeRows = prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`
