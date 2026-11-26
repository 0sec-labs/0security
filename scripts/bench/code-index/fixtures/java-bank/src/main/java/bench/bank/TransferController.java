package bench.bank;

import java.security.Principal;
import java.util.Map;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/transfers")
public class TransferController {
    private final TransferService transfers;
    private final AccountService accounts;

    public TransferController(TransferService transfers, AccountService accounts) {
        this.transfers = transfers;
        this.accounts = accounts;
    }

    @PostMapping
    public Transfer create(@RequestBody Map<String, Object> body, Principal user) {
        Account from = accounts.find(((Number) body.get("from")).longValue());
        accounts.assertOwns(user.getName(), from);
        return transfers.create(from, ((Number) body.get("to")).longValue(), ((Number) body.get("cents")).longValue(), user.getName());
    }

    @PostMapping("/{id}/approve")
    public Transfer approve(@PathVariable long id, Principal user) {
        Transfer transfer = transfers.find(id);
        return transfers.approve(transfer, user.getName());
    }
}
