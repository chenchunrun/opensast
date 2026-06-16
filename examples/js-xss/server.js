const express = require("express");
const { exec } = require("child_process");

const app = express();
app.use(express.json());

app.get("/hello", (req, res) => {
  const name = req.query.name || "";
  // Vulnerable: reflected XSS
  res.send(`<h1>Hello ${name}</h1>`);
});

app.get("/run", (req, res) => {
  const cmd = req.query.cmd || "";
  // Vulnerable: command injection
  exec(cmd, (err, stdout) => res.send(stdout || String(err)));
});

app.listen(3000);
