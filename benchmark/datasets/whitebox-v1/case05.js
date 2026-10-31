const { exec } = require("child_process");
app.get("/lookup", (req, res) => {
  const host = req.query.host;
  exec("nslookup " + host, (error, stdout) => res.send(stdout));
});
