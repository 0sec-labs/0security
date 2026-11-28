package com.ledger.statement;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class StatementRepository {

    private final Map<String, Statement> store = new ConcurrentHashMap<>();

    public Statement save(Statement statement) {
        store.put(statement.id(), statement);
        return statement;
    }

    public Optional<Statement> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Statement> findByOwner(String tenantId, String ownerId) {
        return store.values().stream()
                .filter(s -> s.tenantId().equals(tenantId) && s.ownerId().equals(ownerId))
                .sorted(Comparator.comparing(Statement::id))
                .toList();
    }
}
