import javax.naming.Context;
import javax.naming.InitialContext;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class VulnerableService {

    // Hardcoded credentials
    private static final String DB_PASSWORD = "SuperSecret123!";
    private static final String API_KEY = "sk-1234567890abcdef1234567890abcdef";

    public ResultSet getUser(String userId) throws Exception {
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/db", "root", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        // SQL injection
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return stmt.executeQuery(query);
    }

    public Object lookupJndi(String jndiName) throws Exception {
        // JNDI injection
        Context ctx = new InitialContext();
        return ctx.lookup(jndiName);
    }

    public void executeCommand(String input) throws Exception {
        // Command injection
        Runtime.getRuntime().exec("sh -c " + input);
    }

    public void unsafeDeserialize(byte[] data) throws Exception {
        // Insecure deserialization
        java.io.ObjectInputStream ois = new java.io.ObjectInputStream(
            new java.io.ByteArrayInputStream(data));
        Object obj = ois.readObject();
    }
}
