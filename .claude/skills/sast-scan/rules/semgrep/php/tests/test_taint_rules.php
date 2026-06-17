<?php
// PHP taint-mode rule test fixtures.
// Each rule verifies that Semgrep tracks data flow from superglobals
// through intermediate variables into dangerous sinks.

// --- taint-sql-injection ---

function taintSql_Direct(): void {
    $id = $_GET['id'];
    $conn = mysqli_connect('localhost', 'root', '', 'test');
    // ruleid: php.security.taint-sql-injection
    mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
}

function taintSql_Indirect(): void {
    $name = $_POST['name'];
    $sql = sprintf("SELECT * FROM users WHERE name = '%s'", $name);
    $pdo = new PDO('...');
    // ruleid: php.security.taint-sql-injection
    $pdo->query($sql);
}

function taintSql_StringInterpolation(): void {
    $user = $_REQUEST['user'];
    // ruleid: php.security.taint-sql-injection
    $result = mysql_query("SELECT * FROM users WHERE name = '$user'");
}

function taintSql_Safe(): void {
    $id = $_GET['id'];
    $safeId = (int) $id;
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    // ok: php.security.taint-sql-injection
    $stmt->execute([$safeId]);
}

// --- taint-command-injection ---

function taintCmd_Direct(): void {
    $host = $_GET['host'];
    // ruleid: php.security.taint-command-injection
    exec("ping -c 1 " . $host);
}

function taintCmd_Indirect(): void {
    $file = $_POST['file'];
    $cmd = sprintf("cat %s", $file);
    // ruleid: php.security.taint-command-injection
    system($cmd);
}

function taintCmd_Safe(): void {
    $host = $_GET['host'];
    // ok: php.security.taint-command-injection
    exec("ping -c 1 " . escapeshellarg($host));
}

// --- taint-file-inclusion ---

function taintInclude_Direct(): void {
    $page = $_GET['page'];
    // ruleid: php.security.taint-file-inclusion
    include($page . ".php");
}

function taintInclude_Indirect(): void {
    $template = $_REQUEST['template'];
    $path = "/views/" . $template;
    // ruleid: php.security.taint-file-inclusion
    require_once($path);
}

function taintInclude_Safe(): void {
    // ok: php.security.taint-file-inclusion
    include("header.php");
    // ok: php.security.taint-file-inclusion
    require_once(realpath($_GET['page']));
}

// --- taint-path-traversal ---

function taintPath_Direct(): void {
    $file = $_GET['file'];
    // ruleid: php.security.taint-path-traversal
    readfile("/var/exports/" . $file);
}

function taintPath_Indirect(): void {
    $name = $_POST['name'];
    $path = "/data/" . $name . ".json";
    // ruleid: php.security.taint-path-traversal
    $content = file_get_contents($path);
}

function taintPath_Safe(): void {
    $file = $_FILES['upload']['name'];
    $safe = basename($file);
    // ok: php.security.taint-path-traversal
    move_uploaded_file($_FILES['upload']['tmp_name'], "/uploads/" . $safe);
}

// --- taint-xss ---

function taintXss_Direct(): void {
    $name = $_GET['name'];
    // ruleid: php.security.taint-xss
    print "Hello, " . $name;
}

function taintXss_Indirect(): void {
    $msg = $_POST['message'];
    $output = "<div>" . $msg . "</div>";
    // ruleid: php.security.taint-xss
    print $output;
}

function taintXss_Safe(): void {
    $name = $_GET['name'];
    // ok: php.security.taint-xss
    echo htmlspecialchars($name);
}

// --- taint-deserialize ---

function taintDeserialize_Direct(): void {
    $data = $_POST['payload'];
    // ruleid: php.security.taint-deserialize
    $obj = unserialize($data);
}

function taintDeserialize_Cookie(): void {
    $session = $_COOKIE['session_data'];
    // ruleid: php.security.taint-deserialize
    $obj = unserialize(base64_decode($session));
}

function taintDeserialize_Safe(): void {
    // ok: php.security.taint-deserialize
    $obj = unserialize('a:2:{s:4:"name";s:4:"test";}', ['allowed_classes' => false]);
}
