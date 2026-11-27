import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.springframework.jdbc.core.JdbcTemplate;

// None of these sinks may be reported by the injection rules.
public class SafeInjection extends HttpServlet {
    private JdbcTemplate jdbc;
    private static final String BASE = "/srv/data/";

    // The request value never reaches the sink: dead branch, constant
    // reassignment, constant element, constant key.
    void constantFlows(HttpServletRequest request) throws Exception {
        String value = request.getParameter("v");
        int limit = 40;
        String folded = (3 * 9) + limit > 50 ? "fixed" : value;
        new FileReader(BASE + folded);
        Runtime.getRuntime().exec("echo " + folded);

        String replaced = request.getParameter("w");
        replaced = "constant";
        new FileInputStream(new File(BASE + replaced));

        List<String> items = new ArrayList<String>();
        items.add("first");
        items.add(value);
        items.add("last");
        items.remove(1);
        new FileReader(BASE + items.get(1));

        Map<String, String> map = new HashMap<String, String>();
        map.put("a", "const");
        map.put("b", value);
        new FileReader(BASE + map.get("a"));

        StringBuilder sb = new StringBuilder(value);
        sb = new StringBuilder("fresh");
        Files.readAllBytes(Paths.get(BASE + sb.toString()));
    }

    // The statement text is constant; request values are bound as parameters.
    void parameterised(HttpServletRequest request, Connection connection, DirContext ctx) throws Exception {
        String id = request.getParameter("id");
        PreparedStatement ps = connection.prepareStatement("SELECT * FROM t WHERE id = ?");
        ps.setString(1, id);
        ps.executeQuery();
        jdbc.queryForObject("SELECT n FROM t WHERE id = ?", new Object[] {id}, Long.class);
        jdbc.update("UPDATE t SET a = ? WHERE b = ?", id, id);
        SearchControls sc = new SearchControls();
        ctx.search("ou=users", "(uid={0})", new Object[] {id}, sc);
        XPath xp = XPathFactory.newInstance().newXPath();
        xp.evaluate("/people/person[@id='fixed']", (org.w3c.dom.Document) null);
        Statement st = connection.createStatement();
        st.executeQuery("SELECT 1");
    }

    // A fixed program, a list of fixed arguments plus a request value as data.
    void shellFree(HttpServletRequest request) throws Exception {
        String arg = request.getParameter("a");
        Runtime.getRuntime().exec(new String[] {"/usr/bin/convert", arg});
        new ProcessBuilder("ls", arg).start();
        new ProcessBuilder().command(java.util.Arrays.asList("ls", "-l", arg));
    }

    // Not a request: nothing to report.
    void noRequest(String fromElsewhere) throws Exception {
        new FileReader("/etc/hostname");
        Paths.get("/tmp", "x");
    }
}
