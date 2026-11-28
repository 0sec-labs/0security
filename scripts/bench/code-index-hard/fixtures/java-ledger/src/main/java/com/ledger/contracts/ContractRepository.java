package com.ledger.contracts;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class ContractRepository {

    private final Map<String, Contract> store = new ConcurrentHashMap<>();

    public Contract save(Contract entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<Contract> findByTenantAndId(String tenantId, String id) {
        return Optional.ofNullable(store.get(id)).filter(e -> e.tenantId().equals(tenantId));
    }

    public List<Contract> listByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Contract::id))
                .toList();
    }

    public void removeInTenant(String tenantId, String id) {
        findByTenantAndId(tenantId, id).ifPresent(e -> store.remove(e.id()));
    }
}
