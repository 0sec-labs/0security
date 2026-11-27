import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.springframework.jdbc.core.JdbcTemplate;

// Every marked line must be reported by exactly the rule named in its comment.
public class VulnerableInjection extends HttpServlet {
    private JdbcTemplate jdbc;

    // Request recognised by its declared type, not by its variable name.
    void pathSinks(HttpServletRequest incoming) throws Exception {
        String name = incoming.getParameter("f");
        new FileInputStream(new File("/srv/data/" + name)); // path-traversal
        new FileOutputStream(name); // path-traversal
        new FileReader(name); // path-traversal
        new FileWriter(new File("/srv/out"), name); // path-traversal
        new RandomAccessFile(name, "r"); // path-traversal
        Files.readAllBytes(Paths.get("/srv/data", name)); // path-traversal (Paths.get) + path-traversal (Files)
    }

    // Header, query string and cookie getters, then helpers that keep taint.
    void pathPropagation(HttpServletRequest r2) throws Exception {
        String header = r2.getHeader("X-File");
        String decoded = java.net.URLDecoder.decode(header, "UTF-8");
        new File(decoded); // path-traversal
        String viaBase64 = new String(Base64.getDecoder().decode(r2.getQueryString()));
        new FileReader(viaBase64.trim().substring(1)); // path-traversal
        for (Cookie c : r2.getCookies()) {
            new FileReader(String.format("/srv/%s", c.getValue())); // path-traversal
        }
        StringBuilder sb = new StringBuilder("/srv/");
        sb.append(r2.getParameter("p"));
        new FileReader(sb.toString().replace("..", ".")); // path-traversal
        List<String> names = new ArrayList<String>();
        names.add(r2.getParameter("n"));
        new FileReader(names.get(0)); // path-traversal
    }

    void commands(HttpServletRequest req) throws Exception {
        String arg = req.getParameter("c");
        Runtime.getRuntime().exec("ls " + arg); // command-injection
        Runtime rt = Runtime.getRuntime();
        rt.exec(new String[] {"sh", "-c", arg}); // command-injection
        new ProcessBuilder("sh", "-c", "echo " + arg).start(); // command-injection
        ProcessBuilder pb = new ProcessBuilder();
        List<String> cmd = new ArrayList<String>();
        cmd.add("cmd.exe");
        cmd.add(arg);
        pb.command(cmd); // command-injection
        String[] envp = {arg};
        rt.exec("ls", envp); // command-injection
    }

    void sql(HttpServletRequest request, Connection connection) throws Exception {
        String id = request.getParameter("id");
        Statement st = connection.createStatement();
        st.executeQuery("SELECT * FROM t WHERE id = '" + id + "'"); // sql-injection
        st.executeUpdate("DELETE FROM t WHERE id = " + id); // sql-injection
        st.addBatch("UPDATE t SET a = '" + id + "'"); // sql-injection
        connection.prepareCall("{call p('" + id + "')}"); // sql-injection
        jdbc.queryForObject("SELECT n FROM t WHERE id = '" + id + "'", Long.class); // sql-injection
        jdbc.update("UPDATE t SET a = 1 WHERE b = '" + id + "'"); // sql-injection
        jdbc.queryForList("SELECT * FROM t WHERE id = " + id); // sql-injection
    }

    void ldap(HttpServletRequest request, DirContext ctx) throws Exception {
        String user = request.getParameter("u");
        SearchControls sc = new SearchControls();
        ctx.search("ou=users", "(uid=" + user + ")", sc); // ldap-injection
        ctx.search("ou=users", "(uid=" + user + ")", new Object[] {"x"}, sc); // ldap-injection
    }

    void xpath(HttpServletRequest request, org.w3c.dom.Document doc) throws Exception {
        String who = request.getParameter("w");
        XPath xp = XPathFactory.newInstance().newXPath();
        xp.evaluate("/people/person[@id='" + who + "']", doc); // xpath-injection
        xp.compile("//person[name='" + who + "']"); // xpath-injection
    }
}
