import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// Genuine `static final` constants (and values built from them) stay quiet even
// when the same method also receives request data.
@RestController
public class SafeUpperSnake extends HttpServlet {
    private static final String BASE_COMMAND = "ls";
    private static final String LIST_COMMAND = BASE_COMMAND + " -l";

    @GetMapping("/list")
    void spring(@RequestParam String name) throws Exception {
        Runtime.getRuntime().exec(BASE_COMMAND);
        Runtime.getRuntime().exec(LIST_COMMAND);
        Runtime.getRuntime().exec(SafeUpperSnake.LIST_COMMAND);
    }

    protected void doGet(HttpServletRequest request) throws Exception {
        String ignored = request.getParameter("x");
        Runtime.getRuntime().exec(this.BASE_COMMAND);
    }
}
