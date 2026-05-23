// Insecure CORS tests

// Positive: reflect origin header
// ruleid: javascript.security.insecure-cors
response.headers.set("Access-Control-Allow-Origin", req.headers.get("origin"));

// Positive: wildcard
// ruleid: javascript.security.insecure-cors
res.setHeader("Access-Control-Allow-Origin", "*");

// Positive: reflect dynamic header
// ruleid: javascript.security.insecure-cors
response.headers.set("Access-Control-Allow-Origin", req.headers.get("referer"));

// Negative: literal origin
// ok: javascript.security.insecure-cors
response.headers.set("Access-Control-Allow-Origin", "https://trusted.example.com");

// Negative: specific allowed origin
// ok: javascript.security.insecure-cors
res.setHeader("Access-Control-Allow-Origin", "https://app.example.com");
