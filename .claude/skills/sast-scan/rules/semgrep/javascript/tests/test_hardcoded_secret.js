// Hardcoded secret default tests

// Positive: env with hardcoded default
// ruleid: javascript.security.hardcoded-secret-default
const secret = process.env.SECRET || "default-secret-value";

// Positive: API key with default
// ruleid: javascript.security.hardcoded-secret-default
const apiKey = process.env.API_KEY || "change-me-in-production";

// Positive: token with default
// ruleid: javascript.security.hardcoded-secret-default
const token = process.env.AUTH_TOKEN || "placeholder-token";

// Positive: salt with default
// ruleid: javascript.security.hardcoded-secret-default
const salt = process.env.ENCRYPTION_SALT || "marqdex-default-salt-change-in-production";

// Positive: password with default
// ruleid: javascript.security.hardcoded-secret-default
const pw = process.env.PASSWORD || "admin123";

// Positive: private key with default
// ruleid: javascript.security.hardcoded-secret-default
const key = process.env.PRIVATE_KEY || "-----BEGIN KEY-----";

// Negative: env without secret keyword
// ok: javascript.security.hardcoded-secret-default
const port = process.env.PORT || "3000";

// Negative: env with non-secret name
// ok: javascript.security.hardcoded-secret-default
const host = process.env.HOST || "localhost";

// Negative: env with NODE_ENV
// ok: javascript.security.hardcoded-secret-default
const env = process.env.NODE_ENV || "development";
