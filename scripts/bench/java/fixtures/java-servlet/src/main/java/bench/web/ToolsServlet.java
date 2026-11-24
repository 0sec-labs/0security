package bench.web;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Set;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ToolsServlet extends HttpServlet {
    private static final File BASE = new File("/srv/reports");
    private static final Set<String> HOSTS = Set.of("db1", "db2");

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String action = req.getParameter("action");
        if ("ping".equals(action)) {
            String host = req.getParameter("host");
            Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
            resp.getWriter().println(new String(p.getInputStream().readAllBytes()));
        } else if ("report".equals(action)) {
            String file = req.getParameter("file");
            File target = new File(BASE, file);
            resp.getOutputStream().write(Files.readAllBytes(target.toPath()));
        } else if ("check".equals(action)) {
            String host = req.getParameter("host");
            if (!HOSTS.contains(host)) {
                resp.sendError(400);
                return;
            }
            new ProcessBuilder("ping", "-c", "1", host).start();
        }
    }
}
