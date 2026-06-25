using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Xml;
using System.Runtime.Serialization.Formatters.Binary;

class CsharpRulesTest
{
    void SqlInjection(string userInput)
    {
        var cmd = new System.Data.SqlClient.SqlCommand();
        // ruleid: csharp.security.sql-injection-string-concat
        cmd.CommandText = "SELECT * FROM users WHERE name='" + userInput + "'";

        var safe = new System.Data.SqlClient.SqlCommand();
        // ok: csharp.security.sql-injection-string-concat
        safe.CommandText = "SELECT * FROM users WHERE id=1";
    }

    void CommandInjection(string userInput)
    {
        // ruleid: csharp.security.command-injection-process-start
        Process.Start(userInput);

        // ok: csharp.security.command-injection-process-start
        Process.Start("notepad.exe");
    }

    void PathTraversal(string userPath)
    {
        // ruleid: csharp.security.path-traversal-file
        File.ReadAllText(userPath);

        // ok: csharp.security.path-traversal-file
        File.ReadAllText("/etc/app/config.json");
    }

    void WeakHash()
    {
        // ruleid: csharp.security.weak-hash-md5
        MD5.Create();

        // ok: csharp.security.weak-hash-md5
        SHA256.Create();
    }

    void Deserialization(byte[] data)
    {
        // ruleid: csharp.security.insecure-deserialization
        new BinaryFormatter().Deserialize(new MemoryStream(data));
    }

    void HardcodedSecret()
    {
        // ruleid: csharp.security.hardcoded-credentials
        var password = "SuperSecret123!";

        // ok: csharp.security.hardcoded-credentials
        var passwordFromEnv = Environment.GetEnvironmentVariable("DB_PASSWORD");
    }

    void Ssrf(string url)
    {
        // ruleid: csharp.security.ssrf-webrequest
        WebRequest.Create(url);

        // ok: csharp.security.ssrf-webrequest
        WebRequest.Create("https://api.example.com/health");
    }

    void Xss(string msg, HttpResponse response)
    {
        // ruleid: csharp.security.xss-response-write
        response.Write(msg);

        // ok: csharp.security.xss-response-write
        response.Write("safe static output");
    }

    void LdapInjection(string user, System.DirectoryServices.DirectorySearcher searcher)
    {
        // ruleid: csharp.security.ldap-injection
        searcher.Filter = "(uid=" + user + ")";

        // ok: csharp.security.ldap-injection
        searcher.Filter = "(uid=admin)";
    }

    void XpathInjection(string name, System.Xml.XPath.XPathExpression expr)
    {
        // ruleid: csharp.security.xpath-injection
        System.Xml.XPath.XPathExpression.Compile("//user[name='" + name + "']");

        // ok: csharp.security.xpath-injection
        System.Xml.XPath.XPathExpression.Compile("//user[name='admin']");
    }

    void InsecureRandom()
    {
        // ruleid: csharp.security.insecure-random
        new Random();

        // ok: csharp.security.insecure-random
        RandomNumberGenerator.Create();
    }

    void OpenRedirect(string url, HttpResponse response)
    {
        // ruleid: csharp.security.open-redirect
        response.Redirect(url);

        // ok: csharp.security.open-redirect
        response.Redirect("/home");
    }

    void XmlExternalEntity(string path)
    {
        // ruleid: csharp.security.xml-external-entity
        new XmlDocument();

        // ok: csharp.security.xml-external-entity
        var settings = new System.Xml.XmlReaderSettings();
        System.Xml.XmlReader.Create(path, settings);
    }

    void InsecureCookie()
    {
        var cookie = new HttpCookie("session");
        // ruleid: csharp.security.insecure-cookie
        cookie.Secure = false;
        // ruleid: csharp.security.insecure-cookie
        cookie.HttpOnly = false;

        // ok: csharp.security.insecure-cookie
        var safe = new HttpCookie("token") { Secure = true, HttpOnly = true };
    }

    void InsecureTls()
    {
        // ruleid: csharp.security.insecure-tls
        ServicePointManager.ServerCertificateValidationCallback =
            (sender, cert, chain, errors) => true;

        // ok: csharp.security.insecure-tls — validators that actually check
        ServicePointManager.ServerCertificateValidationCallback =
            (sender, cert, chain, errors) => errors == SslPolicyErrors.None;
    }

    void WeakEncryptionDes()
    {
        // ruleid: csharp.security.weak-encryption-des
        DES.Create();

        // ruleid: csharp.security.weak-encryption-des
        new DESCryptoServiceProvider();

        // ok: csharp.security.weak-encryption-des
        Aes.Create();
    }

    void SensitiveDataLogging(ILogger logger, string password)
    {
        // ruleid: csharp.security.sensitive-data-logging
        logger.LogInformation("Login attempt with password: {Password}", password);

        // ok: csharp.security.sensitive-data-logging
        logger.LogInformation("User {Username} logged in", username);
    }
}
