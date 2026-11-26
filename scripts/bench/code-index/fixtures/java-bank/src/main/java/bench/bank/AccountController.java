package bench.bank;

import java.security.Principal;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/accounts")
public class AccountController {
    private final AccountService accounts;

    public AccountController(AccountService accounts) {
        this.accounts = accounts;
    }

    @GetMapping("/mine")
    public List<Account> mine(Principal user) {
        return accounts.forOwner(user.getName());
    }

    @GetMapping("/{id}")
    public Account read(@PathVariable long id) {
        return accounts.find(id);
    }

    @GetMapping("/{id}/statement")
    public String statement(@PathVariable long id, Principal user) {
        Account account = accounts.find(id);
        accounts.assertOwns(user.getName(), account);
        return accounts.renderStatement(account);
    }
}
