import java.sql.*;

public class TestSqlInjection {
    public void vulnerable(Connection conn, String userId) throws SQLException {
        Statement stmt = conn.createStatement();

        // Positive: string concatenation in executeQuery
        // ruleid: java.security.sql-injection-string-concat
        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

        // ruleid: java.security.sql-injection-string-concat
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + userName + "'");

        // ruleid: java.security.sql-injection-string-concat
        stmt.execute("DELETE FROM users WHERE id = " + userId);

        // ruleid: java.security.sql-injection-string-concat
        stmt.executeUpdate("UPDATE users SET name = '" + userName + "' WHERE id = " + userId);

        // Positive: inline createStatement with concatenation
        // ruleid: java.security.sql-injection-string-concat
        conn.createStatement().executeQuery("SELECT * FROM users WHERE id = " + userId);
    }

    public void safe(Connection conn, String userId) throws SQLException {
        // Negative: PreparedStatement with parameterized query
        // ok: java.security.sql-injection-string-concat
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        pstmt.setString(1, userId);

        // ok: java.security.sql-injection-string-concat
        PreparedStatement pstmt2 = conn.prepareStatement("SELECT * FROM users WHERE name = ? AND active = ?");
        pstmt2.setString(1, userName);
        pstmt2.setBoolean(2, true);
    }
}
