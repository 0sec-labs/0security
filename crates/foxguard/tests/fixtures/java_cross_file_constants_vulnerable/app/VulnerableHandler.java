package app;

import consts.Settings;
import first.*;
import second.*;
import java.io.File;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

// Each path below starts from a constant that is not provably fixed, so the
// request value is still reported even though it is replaced by a literal on
// the live branch.
public class VulnerableHandler extends HttpServlet {
    protected void doGet(HttpServletRequest request) throws IOException {
        String name = request.getParameter("name");
        String chosen;
        if ((7 * 42) - 90 > 200) {
            chosen = "report.txt";
        } else {
            chosen = name;
        }
        new File(Settings.UPLOAD_DIR + chosen).createNewFile(); // path-traversal
        new File(Settings.HOME_DIR + chosen).createNewFile(); // path-traversal
        new File(Settings.CACHE_DIR + chosen).createNewFile(); // path-traversal
        new File(Settings.LOG_DIR + chosen).createNewFile(); // path-traversal
        new File(Roots.DATA_DIR + chosen).createNewFile(); // path-traversal
        new File(Unscanned.BASE_DIR + chosen).createNewFile(); // path-traversal
    }
}
