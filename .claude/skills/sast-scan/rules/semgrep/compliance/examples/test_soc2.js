// SOC 2 compliance rule test fixtures

// --- soc2.access-control-missing-auth ---

// This rule flags route handlers that lack @login_required/@require_auth
// Python: endpoint with auth
// ok: soc2.access-control-missing-auth
@app.route("/api/health")
@login_required
def health():
    return {"status": "ok"}

// Python: endpoint without auth decorator - pattern-either catches bare route handlers
// The rule matches handler functions without @login_required or @require_auth inside them.
// For Semgrep test purposes, a simple route without auth middleware triggers the pattern.
// ruleid: soc2.access-control-missing-auth
@app.route("/api/data")
def get_data():
    return {"data": "sensitive"}

// --- soc2.admin-function-no-role-check ---

// ruleid: soc2.admin-function-no-role-check
app.get("/admin/users", (req, res) => {
    res.json({ users: [] });
});

// ok: soc2.admin-function-no-role-check
app.get("/admin/users", require_role("admin"), (req, res) => {
    res.json({ users: [] });
});

// --- soc2.dependency-no-pinning ---

// ruleid: soc2.dependency-no-pinning
// package.json containing: "lodash": "^4.17.20"
