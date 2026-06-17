<?php
// CWE-98 / CWE-22: File Inclusion / Path Traversal

function testFileInclusion(string $page) {
    // ruleid: php.security.file-inclusion
    include($page);
    // ruleid: php.security.file-inclusion
    require($page . ".php");
    // ruleid: php.security.file-inclusion
    include_once($page);
    // ruleid: php.security.file-inclusion
    require_once($page);

    // ok: php.security.file-inclusion
    include("header.php");
    // ok: php.security.file-inclusion
    require_once("config.php");
}

function testPathTraversal(string $file) {
    // ruleid: php.security.path-traversal
    fopen($file, 'r');
    // ruleid: php.security.path-traversal
    file_get_contents($file);
    // ruleid: php.security.path-traversal
    readfile($file);

    // ok: php.security.path-traversal
    fopen("data.json", "r");
    // ok: php.security.path-traversal
    file_get_contents("config.yml");
}
