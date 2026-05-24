// Test corpus for PHP rules
// Lines with // ruleid: should trigger
// Lines with // ok: should NOT trigger

<?php

// --- sql-injection ---

// ruleid: php.security.sql-injection-string-concat
$conn->query("SELECT * FROM users WHERE id = " . $userId);

// ok: php.security.sql-injection-string-concat
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("s", $userId);

// --- command-injection ---

// ruleid: php.security.command-injection-exec
exec($userInput);

// ruleid: php.security.command-injection-exec
system($userInput);

// ok: php.security.command-injection-exec
exec("ls -la");

// --- eval ---

// ruleid: php.security.eval-usage
eval($userInput);

// ok: php.security.eval-usage
eval("return 1;");

// --- xss ---

// ruleid: php.security.xss-echo-unescaped
echo $userInput;

// --- file-inclusion ---

// ruleid: php.security.file-inclusion
include($userInput);

// ok: php.security.file-inclusion
include("config.php");

// --- header-injection ---

// ruleid: php.security.header-injection
header("Location: " . $userInput);

// --- hardcoded-credentials ---

// ruleid: php.security.hardcoded-credentials
$password = "supersecret123";

// ok: php.security.hardcoded-credentials
$password = getenv("DB_PASSWORD");

// --- weak-hash ---

// ruleid: php.security.weak-hash-md5
md5($data);

// ruleid: php.security.weak-hash-sha1
sha1($data);

// --- insecure-random ---

// ruleid: php.security.insecure-random
rand();

// --- path-traversal ---

// ruleid: php.security.path-traversal
file_get_contents($userInput);

// ok: php.security.path-traversal
file_get_contents("/etc/hosts");

// --- unserialize ---

// ruleid: php.security.unserialize-unsafe
unserialize($userInput);

// --- ssrf ---

// ruleid: php.security.ssrf-file-get-contents
file_get_contents($userUrl);

// ok: php.security.ssrf-file-get-contents
file_get_contents("https://api.example.com");

?>
