package bench.bank;

import java.util.List;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

@Service
public class AccountService {
    private final AccountRepository repo;

    public AccountService(AccountRepository repo) {
        this.repo = repo;
    }

    public Account find(long id) {
        return repo.findById(id);
    }

    public List<Account> forOwner(String owner) {
        return repo.findByOwner(owner);
    }

    public void assertOwns(String user, Account account) {
        if (!account.getOwner().equals(user)) {
            throw new AccessDeniedException("not your account");
        }
    }

    public String renderStatement(Account account) {
        return "Statement for " + account.getId() + ": " + account.getBalanceCents();
    }
}
