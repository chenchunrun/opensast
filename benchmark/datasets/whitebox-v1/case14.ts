app.get("/documents/:id", requireAuth, async (req, res) => {
  const document = await db.document.findFirst({ where: { id: req.params.id, ownerId: req.user.id } });
  if (!document) return res.status(404).end();
  res.json(document);
});
