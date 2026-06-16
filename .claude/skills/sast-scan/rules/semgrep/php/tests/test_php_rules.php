<?php

// ruleid: php.security.sql-injection-string-concat
$conn->query("SELECT * FROM users WHERE id = " . $userId);

// ok: php.security.sql-injection-string-concat
$conn->query("SELECT 1");

// ruleid: php.security.command-injection-exec
exec($userInput);

// ok: php.security.command-injection-exec
exec("ls -la");

// ruleid: php.security.eval-usage
eval($userInput);

// ok: php.security.eval-usage
eval("return 1;");

// ruleid: php.security.xss-echo-unescaped
print $userInput;

// ok: php.security.xss-echo-unescaped
print htmlspecialchars($userInput);

// ruleid: php.security.file-inclusion
include($userInput);

// ok: php.security.file-inclusion
include("config.php");

// ruleid: php.security.header-injection
header("Location: " . $userInput);

// ok: php.security.header-injection
header("Location: /dashboard");

// ruleid: php.security.hardcoded-credentials
$password = "supersecret123";

// ok: php.security.hardcoded-credentials
$password = getenv("DB_PASSWORD");

// ruleid: php.security.insecure-cookie
setcookie("session", $token, 0, "/", "", false, true);

// ok: php.security.insecure-cookie
setcookie("session", $token, time() + 3600, "/", "", true, true);

// ruleid: php.security.session-fixation
session_id($userInput);

// ok: php.security.session-fixation
session_id();

// ruleid: php.security.weak-password-hash
md5($password);

// ok: php.security.weak-password-hash
password_hash($password, PASSWORD_BCRYPT);

// ruleid: php.security.weak-hash-md5
md5($data);

// ruleid: php.security.weak-hash-sha1
sha1($data);

// ok: php.security.weak-hash-md5
hash("sha256", $data);

// ruleid: php.security.insecure-random
rand();

// ok: php.security.insecure-random
random_int(1, 10);

// ruleid: php.security.path-traversal
file_get_contents($userInput);

// ok: php.security.path-traversal
file_get_contents("/etc/hosts");

// ruleid: php.security.unserialize-unsafe
unserialize($userInput);

// ok: php.security.unserialize-unsafe
unserialize("a:0:{}");

// ruleid: php.security.ssrf-file-get-contents
file_get_contents($userUrl);

// ok: php.security.ssrf-file-get-contents
file_get_contents("https://api.example.com");

// ruleid: php.security.debug-enabled
ini_set('display_errors', '1');

// ok: php.security.debug-enabled
ini_set('display_errors', '0');

// Note: APP_DEBUG test cases are commented because the rule uses `languages: [php]`
// with `pattern-regex` which scans raw file content (including comments).
// php.security.laravel-debug-mode
// ruleid: php.security.laravel-debug-mode
// APP_DEBUG=true

// ok: php.security.laravel-debug-mode
// APP_DEBUG=false

// ruleid: php.security.laravel-csrf-disabled
$except = ['*'];

// ok: php.security.laravel-csrf-disabled
$except = ['/webhook'];

// ruleid: php.security.laravel-mass-assignment
User::create($request->all());

// ok: php.security.laravel-mass-assignment
User::create($request->only('name', 'email'));

?>
