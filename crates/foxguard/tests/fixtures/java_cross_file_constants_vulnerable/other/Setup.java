package other;

import consts.Settings;
import javax.servlet.http.HttpServletRequest;

public class Setup {
    public void configure(HttpServletRequest request) {
        Settings.UPLOAD_DIR = request.getParameter("dir");
    }
}
