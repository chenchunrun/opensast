// CSRF bypass tests

// Positive: bypass CSRF in non-production
// ruleid: javascript.security.csrf-bypass-env
if (process.env.NODE_ENV !== "production") {
    return { ok: true }
}

// Negative: proper CSRF check
// ok: javascript.security.csrf-bypass-env
if (!csrfToken) {
    return { error: "Missing CSRF token" }
}
