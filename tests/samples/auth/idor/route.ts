import { NextRequest, NextResponse } from "next/server"
import { auth } from "@/lib/auth"

// IDOR candidate: has auth but no resource-level authorization
export async function DELETE(
    request: NextRequest,
    { params }: { params: { id: string } }
) {
    const session = await auth()
    if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 })

    // Missing: check if session.user.id owns this resource
    await db.project.delete({ where: { id: params.id } })
    return NextResponse.json({ success: true })
}
