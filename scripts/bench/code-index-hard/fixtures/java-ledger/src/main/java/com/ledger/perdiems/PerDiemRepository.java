package com.ledger.perdiems;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class PerDiemRepository {

    private final Map<String, PerDiem> store = new ConcurrentHashMap<>();

    public PerDiem save(PerDiem entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<PerDiem> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<PerDiem> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(PerDiem::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
