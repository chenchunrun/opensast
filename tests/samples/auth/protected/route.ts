import { NextRequest, NextResponse } from "next/server"
import { auth } from "@/lib/auth"

// Protected: has auth + resource authorization
export async function GET(
    request: NextRequest,
    { params }: { params: { id: string } }
) {
    const session = await auth()
    if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 })

    const project = await db.project.findUnique({ where: { id: params.id } })
    if (project.userId !== session.user.id) {
        return NextResponse.json({ error: "Forbidden" }, { status: 403 })
    }
    return NextResponse.json(project)
}
