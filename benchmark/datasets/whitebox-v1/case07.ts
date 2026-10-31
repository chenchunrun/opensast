app.get("/users", async (req, res) => {
  const userId = req.query.id;
  const rows = await db.query("SELECT * FROM users WHERE id=" + userId);
  res.json(rows);
});
