<?php
// PHP SAST test fixtures — per-CWE coverage
// CWE-78: Command Injection

function testCommandInjection(string $userInput) {
    // ruleid: php.security.command-injection-exec
    exec($userInput);
    // ruleid: php.security.command-injection-exec
    system("ping " . $userInput);
    // ruleid: php.security.command-injection-exec
    shell_exec("nslookup " . $userInput);
    // ruleid: php.security.command-injection-exec
    passthru($userInput);

    // ok: php.security.command-injection-exec
    exec(escapeshellcmd($userInput));
    // ok: php.security.command-injection-exec
    system("ls -la");
    // ok: php.security.command-injection-exec
    exec("echo 'safe'");
}
