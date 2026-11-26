package com.ledger.costcenters;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class CostCenterRepository {

    private final Map<String, CostCenter> store = new ConcurrentHashMap<>();

    public CostCenter save(CostCenter entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<CostCenter> findByTenantAndId(String tenantId, String id) {
        return Optional.ofNullable(store.get(id)).filter(e -> e.tenantId().equals(tenantId));
    }

    public List<CostCenter> listByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(CostCenter::id))
                .toList();
    }

    public void removeInTenant(String tenantId, String id) {
        findByTenantAndId(tenantId, id).ifPresent(e -> store.remove(e.id()));
    }
}
