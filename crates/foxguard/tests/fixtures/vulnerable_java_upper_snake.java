import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// An UPPER_SNAKE name that is a parameter, a loop variable or a helper
// parameter is request data, not a constant. Every marked line must be flagged.
@RestController
public class VulnerableUpperSnake extends HttpServlet {
    private static final String BASE_COMMAND = "ls";

    // Spring: the annotated parameter is named like a constant.
    @GetMapping("/run")
    void spring(@RequestParam String USER_INPUT) throws Exception {
        Runtime.getRuntime().exec(USER_INPUT); // command-injection
    }

    // Servlet: the request value reaches a helper whose parameter is named like a constant.
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        run(request.getParameter("cmd"));
        for (String ARG : request.getParameterValues("a")) {
            Runtime.getRuntime().exec(ARG); // command-injection
        }
    }

    private void run(String USER_COMMAND) throws Exception {
        Runtime.getRuntime().exec(USER_COMMAND); // command-injection
    }

    // A parameter shadows the constant field of the same name.
    void shadowed(@RequestParam String BASE_COMMAND) throws Exception {
        Runtime.getRuntime().exec(BASE_COMMAND); // command-injection
    }
}
