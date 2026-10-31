import javax.servlet.http.HttpServletRequest;
class Case11 {
    Object lookup(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        return Runtime.getRuntime().exec(new String[]{"sh", "-c", "nslookup " + host});
    }
}
