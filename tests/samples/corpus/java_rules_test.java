// Test corpus for Java rules
// Lines with // ruleid: should trigger
// Lines with // ok: should NOT trigger

import java.sql.*;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.naming.*;

public class TestCorpus {
    // ruleid: java.security.sql-injection-string-concat
    public void sqlInject(String userId) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:test");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }

    // ok: java.security.sql-injection-string-concat
    public void sqlSafe(String userId) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:test");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userId);
    }

    // ruleid: java.security.command-injection-runtime-exec
    public void cmdInject(String userInput) throws Exception {
        Runtime.getRuntime().exec("ls " + userInput);
    }

    // ok: java.security.command-injection-runtime-exec
    public void cmdSafe() throws Exception {
        Runtime.getRuntime().exec(new String[]{"ls", "-la"});
    }

    // ruleid: java.security.jndi-injection
    public void jndiInject(String userInput) throws Exception {
        Context ctx = new InitialContext();
        ctx.lookup(userInput);
    }

    // ruleid: java.security.path-traversal-file
    public void pathInject(String userInput) throws Exception {
        new FileInputStream(userInput);
    }

    // ok: java.security.path-traversal-file
    public void pathSafe() throws Exception {
        new FileInputStream("/etc/hosts");
    }

    // ruleid: java.security.weak-hash-md5
    public void weakMd5() throws Exception {
        MessageDigest.getInstance("MD5");
    }

    // ruleid: java.security.weak-hash-sha1
    public void weakSha1() throws Exception {
        MessageDigest.getInstance("SHA-1");
    }

    // ruleid: java.security.insecure-random
    public void insecureRandom() {
        new Random();
    }

    // ok: java.security.insecure-random
    public void secureRandom() {
        new SecureRandom();
    }

    // ruleid: java.security.hardcoded-jdbc-password
    public void hardcodedJdbc(String url) throws Exception {
        DriverManager.getConnection(url, "admin", "password123");
    }
}
