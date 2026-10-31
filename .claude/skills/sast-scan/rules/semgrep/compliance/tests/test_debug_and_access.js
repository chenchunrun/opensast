// ruleid: nist800-53.cm6-debug-config-js
const config = { debug: true };
// ok: nist800-53.cm6-debug-config-js
const safeConfig = { debug: false };

function bypass(req, res, next) {
  // ruleid: nist800-53.ac3-access-enforcement
  if (process.env.NODE_ENV !== "production") { return true; }
}

// ruleid: nist800-53.ac7-no-rate-limiting
app.post("/login", loginHandler);
// ok: nist800-53.ac7-no-rate-limiting
app.post("/login", rateLimit(5), loginHandler);

// ruleid: nist800-53.au2-no-audit-log
app.post("/api/users", deleteUser);
