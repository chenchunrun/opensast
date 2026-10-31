import javax.servlet.http.HttpServletRequest;
class Case12 {
    Object lookup(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        return new ProcessBuilder("nslookup", host).start();
    }
}
