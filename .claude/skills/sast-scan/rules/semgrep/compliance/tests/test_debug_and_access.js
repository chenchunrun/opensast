// Fixture layout note: the rule tester pairs an annotation line with the code
// line directly below it, so every code line below is shaped to fire (or stay
// silent) for exactly ONE rule. Cross-rule co-firing lines are avoided by
// adding the other rule's guard.

// ruleid: nist800-53.cm6-debug-config-js
const config = { debug: true };
// ok: nist800-53.cm6-debug-config-js
const safeConfig = { debug: false };

function bypass(req, res, next) {
  // ruleid: nist800-53.ac3-access-enforcement
  if (process.env.NODE_ENV !== "production") { return true; }
}

// rate-limit missing -> ac7 fires; auth guard present -> soc2 stays silent.
// ruleid: nist800-53.ac7-no-rate-limiting
app.post("/login", requireAuth, loginHandler);
// rateLimit present -> ac7 silent; requireAuth present -> soc2 silent.
// ok: nist800-53.ac7-no-rate-limiting
app.post("/login", rateLimit(5), requireAuth, loginHandler);

// any app.post fires au2; requireAuth keeps soc2 silent.
// ruleid: nist800-53.au2-no-audit-log
app.post("/api/users", requireAuth, deleteUser);

// --- soc2.access-control-missing-auth: guard-aware expectations ---

// Unguarded handler -> flagged (get, so ac7/au2 do not apply).
// ruleid: soc2.access-control-missing-auth
app.get("/api/orders", listOrders);

// Rate limiting is not authentication: soc2 still flags the route.
// ruleid: soc2.access-control-missing-auth
app.get("/api/orders", rateLimit(5), listOrders);

// Inline named auth middleware -> suppressed.
// ok: soc2.access-control-missing-auth
app.get("/api/orders", requireAuth, listOrders);

// au2 fires on every .post; the spread auth guard suppresses soc2 only.
// ruleid: nist800-53.au2-no-audit-log
app.post("/api/orders", ...approvalAuth, createOrder);

// Role guard -> suppressed.
// ok: soc2.access-control-missing-auth
app.delete("/api/orders/:id", requireRole("admin"), removeOrder);

// Token verification middleware -> suppressed.
// ok: soc2.access-control-missing-auth
app.put("/api/orders/:id", verifyToken, updateOrder);

// Session middleware -> suppressed.
// ok: soc2.access-control-missing-auth
app.patch("/api/orders/:id", ensureSession, patchOrder);

// Array-form auth middleware -> suppressed.
// ok: soc2.access-control-missing-auth
app.get("/api/orders", [authMiddleware], listOrders);
