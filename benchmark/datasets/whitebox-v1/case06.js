const { execFile } = require("child_process");
app.get("/lookup", (req, res) => {
  const host = req.query.host;
  execFile("nslookup", [host], (error, stdout) => res.send(stdout));
});
