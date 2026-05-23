const { exec, execFile } = require('child_process');

const host = "example.com; rm -rf /";

// Positive: exec with template literal interpolation
// ruleid: javascript.security.command-injection-exec
exec(`ping ${host}`);

// ruleid: javascript.security.command-injection-exec
exec(`curl ${userProvidedUrl}`);

// Positive: exec with string concatenation
// ruleid: javascript.security.command-injection-exec
exec("sh -c " + userInput);

// ruleid: javascript.security.command-injection-exec
exec("ping " + host);

// Negative: exec with literal string
// ok: javascript.security.command-injection-exec
exec("ls");

// ok: javascript.security.command-injection-exec
exec("echo hello");

// Negative: execFile (no shell)
// ok: javascript.security.command-injection-exec
execFile("ping", [host]);
