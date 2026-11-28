import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

class SessionWrites {
    // Request value stored under a fixed attribute name.
    void valueFromParameter(HttpServletRequest request) {
        String id = request.getParameter("id");
        request.getSession().setAttribute("userid", id);
    }

    // Request value used as the attribute name.
    void nameFromHeader(HttpServletRequest request, HttpSession session) {
        String key = request.getHeader("X-Key");
        session.setAttribute(key, "1");
    }

    // Legacy putValue API, value passed through a derived string.
    void legacyPutValue(HttpServletRequest req) {
        String raw = req.getParameter("name");
        String trimmed = raw.trim();
        req.getSession(true).putValue("name", trimmed);
    }
}
