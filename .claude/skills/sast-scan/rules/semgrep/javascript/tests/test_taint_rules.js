const { exec, execSync } = require("child_process");
const fs = require("fs");

function taintSql(req, db) {
  const userId = req.query.id;
  const sql = "SELECT * FROM users WHERE id = " + userId;
  // ruleid: javascript.security.taint-sql-injection
  db.query(sql);

  // ok: javascript.security.taint-sql-injection
  db.query("SELECT * FROM users WHERE id = ?", [1]);
}

function taintCommand(req) {
  const cmd = req.body.cmd;
  // ruleid: javascript.security.taint-command-injection
  exec(cmd);

  // ok: javascript.security.taint-command-injection
  exec("ls -la");
}

function taintXss(req, res) {
  const msg = req.query.msg;
  // ruleid: javascript.security.taint-xss
  res.send(msg);

  // ok: javascript.security.taint-xss
  res.send("static");
}

function taintPath(req) {
  const userPath = req.params.file;
  // ruleid: javascript.security.taint-path-traversal
  fs.readFile(userPath, "utf8", () => {});

  // ok: javascript.security.taint-path-traversal
  fs.readFile("/var/app/data.json", "utf8", () => {});
}

function taintSsrf(req) {
  const url = req.query.url;
  // ruleid: javascript.security.taint-ssrf
  fetch(url);

  // ok: javascript.security.taint-ssrf
  fetch("https://api.example.com/health");
}

function taintRedirect(req, res) {
  const target = req.query.next;
  // ruleid: javascript.security.taint-open-redirect
  res.redirect(target);

  // ok: javascript.security.taint-open-redirect
  res.redirect("/dashboard");
}
