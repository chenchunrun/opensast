import { NextRequest, NextResponse } from "next/server"

// ruleid: taint.sql - user input flows to SQL query
export async function GET(request: NextRequest) {
    const name = request.nextUrl.searchParams.get("name")
    const result = await db.query(`SELECT * FROM users WHERE name = '${name}'`)
    return NextResponse.json(result)
}
