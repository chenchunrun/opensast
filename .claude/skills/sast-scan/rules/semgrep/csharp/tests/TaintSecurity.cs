using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Data.SqlClient;
using System.DirectoryServices;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

// C# taint-mode rule test fixtures.
// Each taint rule requires the data to flow from a web request source
// through (optional) assignments into a dangerous sink, demonstrating
// that Semgrep can follow the data across statements.

class TaintSecurity
{
    // --- taint-sql-injection ---

    void TaintSqlInjection_Direct(HttpRequest req)
    {
        var user = req.Query["user"];
        using var conn = new SqlConnection();
        // ruleid: csharp.security.taint-sql-injection
        conn.ExecuteReader("SELECT * FROM users WHERE name='" + user + "'");
    }

    void TaintSqlInjection_Indirect(HttpRequest req)
    {
        var input = req.QueryString["id"];
        var sql = "SELECT * FROM users WHERE id=" + input;
        using var cmd = new SqlCommand();
        // ruleid: csharp.security.taint-sql-injection
        cmd.CommandText = sql;
    }

    void TaintSqlInjection_Safe(HttpRequest req)
    {
        var id = req.Query["id"];
        using var cmd = new SqlCommand("SELECT * FROM users WHERE id=@id");
        // ok: csharp.security.taint-sql-injection
        cmd.Parameters.Add(new SqlParameter("@id", int.Parse(id)));
    }

    // --- taint-command-injection ---

    void TaintCommandInjection_Direct(HttpRequest req)
    {
        var host = req.Query["host"];
        // ruleid: csharp.security.taint-command-injection
        Process.Start("cmd.exe", "/c ping " + host);
    }

    void TaintCommandInjection_Indirect(HttpRequest req)
    {
        var target = req.Form["target"];
        var psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c nslookup " + target;
        // ruleid: csharp.security.taint-command-injection
        Process.Start(psi);
    }

    void TaintCommandInjection_Safe(HttpRequest req)
    {
        // ok: csharp.security.taint-command-injection
        Process.Start("ping.exe", "localhost");
    }

    // --- taint-path-traversal ---

    void TaintPathTraversal_Direct(HttpRequest req)
    {
        var file = req.Query["file"];
        // ruleid: csharp.security.taint-path-traversal
        File.ReadAllText(file);
    }

    void TaintPathTraversal_Indirect(HttpRequest req)
    {
        var name = req.QueryString["name"];
        var path = Path.Combine("/data/reports", name);
        // ruleid: csharp.security.taint-path-traversal
        File.Open(path, FileMode.Open);
    }

    void TaintPathTraversal_Safe(HttpRequest req)
    {
        var name = req.Query["report"];
        var safe = Path.GetFileName(name);
        // ok: csharp.security.taint-path-traversal
        File.ReadAllText(Path.Combine("/data/reports", safe));
    }

    // --- taint-ssrf ---

    void TaintSsrf_Direct(HttpRequest req)
    {
        var url = req.Query["url"];
        // ruleid: csharp.security.taint-ssrf
        WebRequest.Create(url);
    }

    void TaintSsrf_Indirect(HttpRequest req)
    {
        var endpoint = req.Form["callback"];
        var client = new HttpClient();
        // ruleid: csharp.security.taint-ssrf
        client.GetAsync(endpoint);
    }

    void TaintSsrf_Safe()
    {
        // ok: csharp.security.taint-ssrf
        WebRequest.Create("https://api.example.com/health");
    }

    // --- taint-xss ---

    void TaintXss_Direct(HttpRequest req, HttpResponse resp)
    {
        var msg = req.Query["msg"];
        // ruleid: csharp.security.taint-xss
        resp.Write(msg);
    }

    void TaintXss_Indirect(HttpRequest req, HttpResponse resp)
    {
        var name = req.Form["name"];
        var greeting = "Hello, " + name;
        // ruleid: csharp.security.taint-xss
        resp.Write(greeting);
    }

    void TaintXss_Safe(HttpRequest req, HttpResponse resp)
    {
        var input = req.Query["comment"];
        var encoded = HttpUtility.HtmlEncode(input);
        // ok: csharp.security.taint-xss
        resp.Write(encoded);
    }

    // --- taint-ldap-injection ---

    void TaintLdap_Direct(HttpRequest req, DirectorySearcher searcher)
    {
        var username = req.Query["user"];
        // ruleid: csharp.security.taint-ldap-injection
        searcher.Filter = "(uid=" + username + ")";
    }

    void TaintLdap_Indirect(HttpRequest req, DirectorySearcher searcher)
    {
        var input = req.Form["login"];
        var filter = String.Format("(uid={0})", input);
        // ruleid: csharp.security.taint-ldap-injection
        searcher.Filter = filter;
    }

    void TaintLdap_Safe(HttpRequest req, DirectorySearcher searcher)
    {
        var id = req.Query["id"];
        var safeId = Guid.Parse(id);
        // ok: csharp.security.taint-ldap-injection
        searcher.Filter = "(uid=" + safeId + ")";
    }
}
