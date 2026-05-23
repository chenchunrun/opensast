import java.io.IOException;

public class TestCommandInjection {
    public void vulnerable(String input) throws IOException {
        // Positive: Runtime.exec with string concatenation
        // ruleid: java.security.command-injection-runtime-exec
        Runtime.getRuntime().exec("sh -c " + input);

        // ruleid: java.security.command-injection-runtime-exec
        Runtime.getRuntime().exec("ping " + userInput);

        // ruleid: java.security.command-injection-runtime-exec
        Runtime.getRuntime().exec("curl " + url + " -o output.txt");

        // Positive: String.format in exec
        // ruleid: java.security.command-injection-runtime-exec
        Runtime.getRuntime().exec(String.format("sh -c %s", input));
    }

    public void safe(String[] args) throws IOException {
        // Negative: ProcessBuilder with array
        // ok: java.security.command-injection-runtime-exec
        ProcessBuilder pb = new ProcessBuilder("ls", "-la");
        pb.start();

        // ok: java.security.command-injection-runtime-exec
        ProcessBuilder pb2 = new ProcessBuilder(new String[]{"ping", "-c", "3", "example.com"});
        pb2.start();

        // ok: java.security.command-injection-runtime-exec
        Runtime.getRuntime().exec(new String[]{"ls", "-la"});
    }
}
