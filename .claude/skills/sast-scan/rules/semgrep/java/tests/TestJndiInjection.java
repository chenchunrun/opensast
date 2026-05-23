import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

public class TestJndiInjection {
    public void vulnerable(String userInput) throws NamingException {
        Context ctx = new InitialContext();

        // Positive: lookup with variable input
        // ruleid: java.security.jndi-injection
        ctx.lookup(userInput);

        // ruleid: java.security.jndi-injection
        ctx.lookup(request.getParameter("jndiName"));

        // ruleid: java.security.jndi-injection
        Object obj = ctx.lookup(System.getProperty("lookup.name"));
    }

    public void safe() throws NamingException {
        Context ctx = new InitialContext();

        // Negative: lookup with literal string
        // ok: java.security.jndi-injection
        ctx.lookup("java:comp/env/jdbc/ds");

        // ok: java.security.jndi-injection
        Object ds = ctx.lookup("java:comp/env/ejb/MyBean");
    }
}
