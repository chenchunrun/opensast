use rand::rngs::OsRng;
use std::process::Command;
use std::sync::Mutex;

fn side_effect() {}

struct UnsafeType;
// ruleid: rust.security.unsafe-impl
unsafe impl Send for UnsafeType {}

// ruleid: rust.security.unsafe-fn-pointer
unsafe fn dangerous(ptr: *const i32) -> i32 {
    *ptr
}

fn vulnerable(user_input: String, bytes: &[u8], path: &str, mutex: Mutex<String>) {
    // ruleid: rust.security.unsafe-block
    unsafe { side_effect(); }

    let _x = UnsafeType;

    // ruleid: rust.security.raw-pointer-dereference
    unsafe { *bytes.as_ptr() };

    // ruleid: rust.security.unwrap-panic
    some_option.unwrap();

    // ok: rust.security.unwrap-panic
    some_option.unwrap_or_default();

    // ruleid: rust.security.expect-panic
    some_result.expect("must work");

    // ruleid: rust.security.unchecked-index
    let _ = bytes[index];

    // ok: rust.security.unchecked-index
    if index < len { let _ = bytes[index]; }

    // ruleid: rust.security.ignored-result
    let _ = std::fs::read_to_string(path);

    // ruleid: rust.security.command-injection
    Command::new("sh").arg("-c").arg(user_input.clone());

    // ok: rust.security.command-injection
    Command::new("ls").arg("-la");

    // ruleid: rust.security.sql-injection-format
    format!("SELECT * FROM users WHERE name = {}", user_input);

    // ok: rust.security.sql-injection-format
    "SELECT * FROM users WHERE name = $1";

    // ruleid: rust.security.format-string
    println!(user_input);

    // ok: rust.security.format-string
    println!("{}", user_input);

    // ruleid: rust.security.hardcoded-credentials
    let password = "supersecret123";

    // ok: rust.security.hardcoded-credentials
    let password = std::env::var("DB_PASSWORD");

    // ruleid: rust.security.insecure-random
    rand::thread_rng();

    // ok: rust.security.insecure-random
    let _ = OsRng;

    // ruleid: rust.security.ssl-verify-disabled
    builder.danger_accept_invalid_certs(true);

    // ruleid: rust.security.unwrap-or-default-secret
    std::env::var("SECRET").unwrap_or("dev-secret");

    // ruleid: rust.security.mutex-poisoning
    mutex.lock().unwrap();

    // ruleid: rust.security.file-permission
    std::fs::File::open(path).unwrap().set_permissions(0o666);

    // ruleid: rust.security.tempfile-insecure
    std::env::temp_dir().join("my-temp");

    // ruleid: rust.security.path-traversal
    std::fs::read_to_string(path);

    // ok: rust.security.path-traversal
    std::fs::read_to_string("/etc/hosts");

    // ruleid: rust.security.integer-overflow
    let _ = x + y;

    // ok: rust.security.integer-overflow
    let _ = x.checked_add(y);
}
