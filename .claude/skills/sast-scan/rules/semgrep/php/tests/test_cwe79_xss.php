<?php
// CWE-79: Cross-Site Scripting

function testXss(string $name, string $msg) {
    // ruleid: php.security.xss-echo-unescaped
    print $name;
    // ruleid: php.security.xss-echo-unescaped
    printf("Hello %s", $msg);

    // ok: php.security.xss-echo-unescaped
    print htmlspecialchars($name);
    // ok: php.security.xss-echo-unescaped
    echo "Hello World";
}
