import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.servlet.http.HttpServletRequest;
class Case10 {
    Object load(Connection db, HttpServletRequest request) throws Exception {
        PreparedStatement stmt = db.prepareStatement("SELECT * FROM users WHERE id=?");
        stmt.setString(1, request.getParameter("id"));
        return stmt.executeQuery();
    }
}
