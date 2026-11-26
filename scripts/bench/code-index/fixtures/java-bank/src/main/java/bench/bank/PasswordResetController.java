package bench.bank;

import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/password")
public class PasswordResetController {
    private final ResetTokenRepository tokens;
    private final CustomerRepository customers;

    public PasswordResetController(ResetTokenRepository tokens, CustomerRepository customers) {
        this.tokens = tokens;
        this.customers = customers;
    }

    @PostMapping("/reset/request")
    public void request(@RequestBody Map<String, String> body) {
        Customer c = customers.findByEmail(body.get("email"));
        if (c != null) {
            tokens.issueFor(c.getId());
        }
    }

    @PostMapping("/reset/confirm")
    public void confirm(@RequestBody Map<String, String> body) {
        ResetToken token = tokens.find(body.get("token"));
        if (token == null || token.isExpired()) {
            throw new IllegalArgumentException("bad token");
        }
        Customer c = customers.findById(Long.parseLong(body.get("customerId")));
        c.setPassword(body.get("newPassword"));
        customers.save(c);
        tokens.consume(token);
    }
}
