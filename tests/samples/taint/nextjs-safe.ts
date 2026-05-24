import { NextRequest, NextResponse } from "next/server"
import { z } from "zod"

// ok: sanitized with Zod before use
export async function POST(request: NextRequest) {
    const schema = z.object({ name: z.string().max(50) })
    const body = await request.json()
    const data = schema.parse(body)
    const result = await db.query("SELECT * FROM users WHERE name = ?", [data.name])
    return NextResponse.json(result)
}
