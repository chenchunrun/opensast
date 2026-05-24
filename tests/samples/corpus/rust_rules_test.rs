// Test corpus for Rust rules
// Lines with // ruleid: should trigger
// Lines with // ok: should NOT trigger

use std::process::Command;
use std::env;

fn test_command_injection() {
    // --- command-injection ---

    // ruleid: rust.security.command-injection
    Command::new("sh").arg("-c").arg(user_input);

    // ok: rust.security.command-injection
    Command::new("ls").arg("-la");
}

fn test_sql_injection() {
    // --- sql-injection ---

    // ruleid: rust.security.sql-injection-format
    format!("SELECT * FROM users WHERE id = {} ...", user_input);

    // ok: rust.security.sql-injection-format
    "SELECT * FROM users WHERE id = $1";
}

fn test_hardcoded() {
    // --- hardcoded-credentials ---

    // ruleid: rust.security.hardcoded-credentials
    let password = "supersecret123";

    // ok: rust.security.hardcoded-credentials
    let password = env::var("DB_PASSWORD");
}

fn test_ssl() {
    // --- ssl-verify-disabled ---

    // ruleid: rust.security.ssl-verify-disabled
    builder.danger_accept_invalid_certs(true);

fn test_unwrap() {
    // --- unwrap-panic ---

    // ruleid: rust.security.unwrap-panic
    some_value.unwrap();
}

fn test_unsafe() {
    // --- unsafe-block ---

    // ruleid: rust.security.unsafe-block
    unsafe { *ptr }
}
