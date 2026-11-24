package bench.safe;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Set;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeServlet extends HttpServlet {
    private static final Set<String> REPORTS = Set.of("daily.txt", "weekly.txt");
    private static final File BASE = new File("/srv/reports");
    private final Connection db;

    public SafeServlet(Connection db) {
        this.db = db;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("report");
        if (!REPORTS.contains(name)) {
            resp.sendError(404);
            return;
        }
        resp.getOutputStream().write(Files.readAllBytes(new File(BASE, name).toPath()));
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            PreparedStatement ps = db.prepareStatement("SELECT title FROM posts WHERE author = ?");
            ps.setString(1, req.getParameter("author"));
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                resp.getWriter().println(org.apache.commons.text.StringEscapeUtils.escapeHtml4(rs.getString(1)));
            }
        } catch (Exception e) {
            resp.sendError(500);
        }
    }
}
