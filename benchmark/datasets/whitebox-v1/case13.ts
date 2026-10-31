app.get("/documents/:id", requireAuth, async (req, res) => {
  const document = await db.document.findUnique({ where: { id: req.params.id } });
  res.json(document);
});
