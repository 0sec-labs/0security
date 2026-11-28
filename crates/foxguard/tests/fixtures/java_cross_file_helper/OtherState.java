import javax.servlet.http.HttpServletRequest;

// A public static field that request data is assigned to.
public class OtherState {
    public static String USER_COMMAND;

    static void remember(HttpServletRequest request) {
        USER_COMMAND = request.getParameter("cmd");
    }
}
