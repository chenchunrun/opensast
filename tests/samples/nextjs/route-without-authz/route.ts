import { getNextResponse } from "next/server"
import { getFile } from "@/lib/services/file-service"

export async function GET(request, { params }) {
  const fileId = params.id
  const file = await getFile(fileId)
  return NextResponse.json(file)
}
