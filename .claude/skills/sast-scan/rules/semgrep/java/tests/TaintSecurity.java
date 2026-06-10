package tests;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class TaintSecurity {

    public void sqlInjection(HttpServletRequest request, java.sql.Connection connection)
            throws Exception {
        String param = request.getParameter("input");
        String sql = "SELECT * FROM users WHERE name='" + param + "'";
        // ruleid: java.security.taint-sql-injection
        connection.prepareStatement(sql);

        String safe = "SELECT * FROM users WHERE id=1";
        // ok: java.security.taint-sql-injection
        connection.prepareStatement(safe);
    }

    public void commandInjection(HttpServletRequest request) throws Exception {
        String param = request.getHeader("X-Cmd");
        java.util.List<String> args = new java.util.ArrayList<String>();
        args.add("sh");
        args.add(param);
        // ruleid: java.security.taint-command-injection
        new ProcessBuilder(args);

        java.util.List<String> fixed = new java.util.ArrayList<String>();
        fixed.add("ls");
        // ok: java.security.taint-command-injection
        new ProcessBuilder(fixed);
    }

    public void pathTraversal(HttpServletRequest request) throws Exception {
        String param = request.getParameter("file");
        // ruleid: java.security.taint-path-traversal
        new java.io.FileInputStream(param);

        // ok: java.security.taint-path-traversal
        new java.io.FileInputStream("/etc/app/config.properties");
    }

    public void ldapInjection(
            HttpServletRequest request, javax.naming.directory.DirContext ctx) throws Exception {
        String param = request.getParameter("user");
        String filter = "(uid=" + param + ")";
        // ruleid: java.security.taint-ldap-injection
        ctx.search("ou=users", filter, null);

        // ok: java.security.taint-ldap-injection
        ctx.search("ou=users", "(uid=admin)", null);
    }

    public void xpathInjection(HttpServletRequest request, javax.xml.xpath.XPath xp)
            throws Exception {
        String param = request.getParameter("q");
        String expr = "//user[name='" + param + "']";
        // ruleid: java.security.taint-xpath-injection
        xp.compile(expr);

        // ok: java.security.taint-xpath-injection
        xp.compile("//user[name='admin']");
    }

    public void xss(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("msg");
        // ruleid: java.security.taint-xss-servlet
        response.getWriter().println(param);

        String encoded = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);
        // ok: java.security.taint-xss-servlet
        response.getWriter().println(encoded);
    }

    public void trustBoundary(HttpServletRequest request, HttpSession session) {
        String param = request.getParameter("role");
        // ruleid: java.security.taint-trust-boundary
        session.setAttribute("userRole", param);

        // ok: java.security.taint-trust-boundary
        session.setAttribute("userRole", "guest");
    }

    public void weakCipher() throws Exception {
        // ruleid: java.security.weak-cipher-algorithm
        javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");
        // ruleid: java.security.weak-cipher-algorithm
        javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ok: java.security.weak-cipher-algorithm
        javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
    }

    public void insecureCookie(HttpServletResponse response) {
        Cookie c = new Cookie("session", "value");
        // ruleid: java.security.insecure-cookie
        response.addCookie(c);
    }

    public void secureCookie(HttpServletResponse response) {
        Cookie d = new Cookie("session", "value");
        d.setSecure(true);
        // ok: java.security.insecure-cookie
        response.addCookie(d);
    }
}
