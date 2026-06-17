<?php
// CWE-502: Insecure Deserialization / CWE-798: Hardcoded Credentials

function testUnserialize(string $data): void {
    // ruleid: php.security.unserialize-unsafe
    $obj = unserialize($data);

    // ok: php.security.unserialize-unsafe
    $obj = unserialize('a:2:{s:4:"name";s:4:"test";}');
}

function testHardcodedCredentials(): void {
    // ruleid: php.security.hardcoded-credentials
    $password = "admin123";
    // ruleid: php.security.hardcoded-credentials
    $db_pass = "secret_db_password";
    // ruleid: php.security.hardcoded-credentials
    $api_key = "sk-proj-1234567890abcdef";

    // ok: php.security.hardcoded-credentials
    $password = getenv('DB_PASSWORD');
    // ok: php.security.hardcoded-credentials
    $api_key = $_ENV['API_KEY'];
}
