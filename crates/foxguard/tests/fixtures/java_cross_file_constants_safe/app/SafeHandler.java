package app;

import consts.FileConstants;
import consts.Mode;
import consts.Roots;
import java.io.File;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

// Paths built from constants of other files and a request value that is
// replaced by a constant before it is used: nothing here is reported.
public class SafeHandler extends HttpServlet implements Roots {
    protected void doGet(HttpServletRequest request) throws IOException {
        String name = request.getParameter("name");
        String chosen;
        if ((7 * 42) - 90 > 200) {
            chosen = "report.txt";
        } else {
            chosen = name;
        }
        new File(FileConstants.BASE_DIR + chosen).createNewFile();
        new File(FileConstants.LOG_DIR + chosen).createNewFile();
        new File(consts.FileConstants.WORK_DIR + chosen).createNewFile();
        new File(ARCHIVE_DIR + chosen).createNewFile();
        new File(Roots.ARCHIVE_DIR + chosen).createNewFile();
        String mode = Mode.READ + "/" + chosen;
        new File(FileConstants.BASE_DIR + mode).createNewFile();
    }
}
