using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
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
}
