export async function getFile(fileId: string) {
  return db.file.findUnique({ where: { id: fileId } })
}

export async function getFileForUser(fileId: string, userId: string) {
  return db.file.findUnique({ where: { id: fileId, userId: userId } })
}
