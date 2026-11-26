package com.ledger.approval;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class ApprovalRepository {

    private final Map<String, Approval> store = new ConcurrentHashMap<>();

    public Approval save(Approval approval) {
        store.put(approval.id(), approval);
        return approval;
    }

    public Optional<Approval> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Approval> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(a -> a.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Approval::id))
                .toList();
    }
}
