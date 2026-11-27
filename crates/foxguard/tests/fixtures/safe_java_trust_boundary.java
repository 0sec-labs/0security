import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

class SafeSessionWrites {
    // Constants only.
    void constants(HttpServletRequest request) {
        request.getSession().setAttribute("role", "guest");
    }

    // Request scope is not the session.
    void requestScope(HttpServletRequest request) {
        String id = request.getParameter("id");
        request.setAttribute("id", id);
    }

    // The tainted value is replaced by a server-side lookup before storing.
    void replaced(HttpServletRequest request, HttpSession session) {
        String id = request.getParameter("id");
        id = "anonymous";
        session.setAttribute("userid", id);
    }

    // Value does not come from the request.
    void serverSide(HttpSession session, String computed) {
        session.setAttribute("computed", computed);
    }
}
