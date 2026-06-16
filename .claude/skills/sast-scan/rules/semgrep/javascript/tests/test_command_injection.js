const { exec, execFile, execSync } = require('child_process');

const host = "example.com; rm -rf /";

// Positive: exec with template literal interpolation
// ruleid: javascript.security.command-injection-exec
exec(`ping ${userInput}`);

// ruleid: javascript.security.command-injection-exec
exec(`curl ${userProvidedUrl}`);

// Positive: exec with string concatenation
// ruleid: javascript.security.command-injection-exec
exec("sh -c " + userInput);

// ruleid: javascript.security.command-injection-exec
exec("ping " + userInput);

// Positive: execSync with interpolation
// ruleid: javascript.security.command-injection-exec
execSync(`rm ${fileName}`);

// ruleid: javascript.security.command-injection-exec
execSync("ls " + userDir);

// Negative: exec with literal string
// ok: javascript.security.command-injection-exec
exec("ls");

// ok: javascript.security.command-injection-exec
exec("echo hello");

// ok: javascript.security.command-injection-exec
execSync("echo done");

// Negative: execFile (no shell)
// ok: javascript.security.command-injection-exec
execFile("ping", [host]);

// Negative: fetch with template literal API path (NOT exec)
// ok: javascript.security.command-injection-exec
fetch(`/api/tasks/${taskId}`);

// Negative: redirect with template literal (NOT exec)
// ok: javascript.security.command-injection-exec
NextResponse.redirect(`${appUrl}/login?verified=true`);

// Negative: console.log (NOT exec)
// ok: javascript.security.command-injection-exec
console.log(`User ${userId} logged in`);

// Negative: function named somethingElse (NOT exec)
// ok: javascript.security.command-injection-exec
someFunction(`value ${dynamic}`);
