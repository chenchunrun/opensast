import CryptoKit
import Foundation
import os.log

struct SessionState {
    var password: String
    var token: String
}

func vulnerable(user: SessionState, password: String, token: String) {
    // ruleid: swift.security.hardcoded-credentials
    let password = "super-secret-password"

    // ruleid: swift.security.hardcoded-credentials
    let apiKey = "ios-api-key"

    // ok: swift.security.hardcoded-credentials
    let keyFromKeychain = readKeychainValue()

    // ruleid: swift.security.insecure-random
    arc4random()

    // ruleid: swift.security.insecure-random
    arc4random_uniform(1000)

    // ok: swift.security.insecure-random
    let generator = SystemRandomNumberGenerator()
    _ = generator

    // ruleid: swift.security.weak-hash-md5
    Insecure.MD5.hash(data: Data())

    // ruleid: swift.security.weak-hash-md5
    Insecure.SHA1.hash(data: Data())

    // ok: swift.security.weak-hash-md5
    SHA256.hash(data: Data())

    // ruleid: swift.security.insecure-cookie
    HTTPCookie(properties: [.domain: "example.com", .path: "/", .name: "sid", .value: "123"])

    // ok: swift.security.insecure-cookie
    HTTPCookie(properties: [.domain: "example.com", .path: "/", .name: "sid", .value: "123", .secure: "TRUE"])

    // ruleid: swift.security.keychain-insecure
    kSecAttrAccessible = kSecAttrAccessibleAlways

    // ruleid: swift.security.keychain-insecure
    kSecAttrAccessible = .alwaysThisDeviceOnly

    // ok: swift.security.keychain-insecure
    kSecAttrAccessible = .whenUnlockedThisDeviceOnly

    // ruleid: swift.security.ssl-pinning-disabled
    allowsAnyHTTPSCertificate = true

    // ruleid: swift.security.ssl-pinning-disabled
    allowsAnyHTTPSCertificate(forHost: "api.example.com")

    // ok: swift.security.ssl-pinning-disabled
    validatePinnedCertificate(forHost: "api.example.com")

    // ruleid: swift.security.logging-sensitive
    print(user.password)

    // ruleid: swift.security.logging-sensitive
    os_log("\(token)")

    // ok: swift.security.logging-sensitive
    print("request finished")

    #if DEBUG
    // ruleid: swift.security.debug-logging
    print(password)
    #endif

    // ok: swift.security.debug-logging
    releaseLogger.info("sanitized")

    // ruleid: swift.security.assert-in-production
    assert(!password.isEmpty)

    // ok: swift.security.assert-in-production
    precondition(!password.isEmpty)
}
