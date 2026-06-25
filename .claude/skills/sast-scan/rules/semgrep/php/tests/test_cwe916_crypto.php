<?php
// CWE-916 / CWE-328: Weak Password Hashing / Weak Crypto

function testWeakPasswordHash(string $password): void {
    // ruleid: php.security.weak-password-hash
    $hash = md5($password);
    // ruleid: php.security.weak-password-hash
    $hash = sha1($password);

    // ok: php.security.weak-password-hash
    $hash = password_hash($password, PASSWORD_BCRYPT);
}

function testWeakHashData(): void {
    // ruleid: php.security.weak-hash-md5
    $checksum = md5('some-data');
    // ruleid: php.security.weak-hash-sha1
    $checksum = sha1('some-data');

    // ok: php.security.weak-hash-md5
    $hash = hash('sha256', 'data');
    // ok: php.security.weak-hash-sha1
    $hash = hash('sha512', 'data');

    // ok: php.security.weak-password-hash  (no password keyword in arg)
    $checksum = md5('checksum-value');
}
