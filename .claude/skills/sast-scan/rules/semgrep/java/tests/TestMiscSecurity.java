import java.io.*;
import java.net.URL;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import javax.el.ExpressionFactory;
import javax.naming.directory.DirContext;
import javax.net.ssl.X509TrustManager;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.multipart.MultipartFile;

public class TestMiscSecurity extends HttpServlet {
    private String sharedState = "unsafe";

    public void vulnerable(
        String userInput,
        HttpServletRequest request,
        HttpServletResponse response,
        MultipartFile file,
        DirContext ctx,
        ObjectInputStream ois,
        TemplateEngine tmpl,
        VelocityEngine vel,
        DriverManager dm
    ) throws Exception {
        // ruleid: java.security.ssrf-url-open
        new URL(userInput).openConnection();

        // ok: java.security.ssrf-url-open
        new URL("https://api.example.com").openConnection();

        // ruleid: java.security.path-traversal-file
        new FileInputStream(userInput);

        // ok: java.security.path-traversal-file
        new File("/etc/hosts");

        // ruleid: java.security.xxe-xml-parser
        DocumentBuilderFactory.newInstance();

        // ok: java.security.xxe-xml-parser
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        // ruleid: java.security.insecure-random
        new Random();

        // ok: java.security.insecure-random
        new SecureRandom();

        // ruleid: java.security.spring-csrf-disabled
        http.csrf().disable();

        // ruleid: java.security.spring-cors-wildcard
        registry.allowedOrigins("*");

        // ruleid: java.security.spring-permit-all
        auth.permitAll();

        // ruleid: java.security.weak-hash-md5
        MessageDigest.getInstance("MD5");

        // ruleid: java.security.weak-hash-sha1
        MessageDigest.getInstance("SHA-1");

        // ok: java.security.weak-hash-sha1
        MessageDigest.getInstance("SHA-256");

        class TrustAllManager implements X509TrustManager {
            // ruleid: java.security.insecure-ssl-trustall
            public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) { }
            // ruleid: java.security.insecure-ssl-trustall
            public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) { }
            // ruleid: java.security.insecure-ssl-trustall
            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
        }

        // ruleid: java.security.deserialization-objectinput
        ois.readObject();

        // ruleid: java.security.el-injection
        fac.createValueExpression(userInput, Object.class);

        // ok: java.security.el-injection
        fac.createValueExpression("${safe}", Object.class);

        // ruleid: java.security.template-injection
        tmpl.process(userInput, ctx);

        // ok: java.security.template-injection
        tmpl.process("safe-template", ctx);

        // ruleid: java.security.ldap-injection
        ctx.search("ou=users", "(uid=" + userInput + ")", null);

        // ok: java.security.ldap-injection
        ctx.search("ou=users", "(uid=alice)", null);

        // ruleid: java.security.log-injection
        log.info(request.getParameter("username"));

        // ok: java.security.log-injection
        log.info("user login");

        // ruleid: java.security.multipart-upload
        request.getFile("upload");

        // ok: java.security.multipart-upload
        if (file.getSize() > 1024) { return; }
        request.getFile("upload");

        // ruleid: java.security.hardcoded-jdbc-password
        DriverManager.getConnection(url, "user", "pass123");

        // ruleid: java.security.thread-safety-servlet
        sharedState = userInput;

        // ruleid: java.security.tempfile-insecure
        File.createTempFile("report", ".tmp");

        // ruleid: java.security.runtime-exec-shell
        new ProcessBuilder("sh", "-c", userInput);
    }
}
