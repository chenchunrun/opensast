import java.sql.Connection;
import javax.servlet.http.HttpServletRequest;
class Case09 {
    Object load(Connection db, HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        return db.createStatement().executeQuery("SELECT * FROM users WHERE id=" + id);
    }
}
