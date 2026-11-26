package com.ledger.statement;

import com.ledger.common.Access;
import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import com.ledger.security.ShareTokenService;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class StatementService {

    private final StatementRepository repository;
    private final ShareTokenService shareTokens;

    public StatementService(StatementRepository repository, ShareTokenService shareTokens) {
        this.repository = repository;
        this.shareTokens = shareTokens;
    }

    /**
     * Builds the statement for an account. Callers are responsible for authorizing access to the account.
     */
    public StatementView build(String accountId) {
        Statement statement = repository.findById(accountId).orElseThrow(() -> new NotFoundException("statement"));
        return new StatementView(statement.id(), statement.period(), statement.openingCents(), statement.closingCents(),
                statement.lines());
    }

    public StatementView buildFor(AuthUser user, String id) {
        authorize(user, id);
        return build(id);
    }

    public List<StatementView> mine(AuthUser user) {
        return repository.findByOwner(user.tenantId(), user.id()).stream().map(s -> build(s.id())).toList();
    }

    public String share(AuthUser user, String id) {
        authorize(user, id);
        return shareTokens.issue(id);
    }

    private void authorize(AuthUser user, String id) {
        Statement statement = repository.findById(id).orElseThrow(() -> new NotFoundException("statement"));
        Access.requireTenant(user, statement.tenantId());
        Access.requireOwnerOrManager(user, statement.ownerId());
    }
}
