import { getNextResponse } from "next/server"
import { getFileForUser } from "@/lib/services/file-service"

export async function GET(request, { params }) {
  const session = await getServerSession(authOptions)
  const fileId = params.id
  const file = await getFileForUser(fileId, session.user.id)
  return NextResponse.json(file)
}
