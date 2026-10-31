class TestDebug {
    void Configure(Config config) {
        // ruleid: iso27001.a8-9-production-debug-jvm-dotnet
        config.debug = true;
        // ok: iso27001.a8-9-production-debug-jvm-dotnet
        config.debug = false;
    }
}
