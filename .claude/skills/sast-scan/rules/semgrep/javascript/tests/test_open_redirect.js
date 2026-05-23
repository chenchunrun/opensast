// Open redirect tests

// Positive: redirect with user input
// ruleid: javascript.security.open-redirect
res.redirect(userUrl);

// Positive: NextResponse redirect with variable
// ruleid: javascript.security.open-redirect
NextResponse.redirect(appUrl);

// Positive: Response redirect with user input
// ruleid: javascript.security.open-redirect
Response.redirect(userProvidedUrl);

// Negative: redirect to literal URL
// ok: javascript.security.open-redirect
res.redirect("/login");

// Negative: redirect to constructed URL with fixed base
// ok: javascript.security.open-redirect
NextResponse.redirect(new URL("/login", "https://example.com"));
