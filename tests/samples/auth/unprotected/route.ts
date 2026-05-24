import { NextRequest, NextResponse } from "next/server"

// Unprotected: no auth check at all
export async function GET(request: NextRequest) {
    const users = await db.user.findMany()
    return NextResponse.json(users)
}

export async function POST(request: NextRequest) {
    const body = await request.json()
    const user = await db.user.create({ data: body })
    return NextResponse.json(user)
}
