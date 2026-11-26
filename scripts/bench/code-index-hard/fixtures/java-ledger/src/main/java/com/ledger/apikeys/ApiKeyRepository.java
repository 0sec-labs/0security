package com.ledger.apikeys;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class ApiKeyRepository {

    private final Map<String, ApiKey> store = new ConcurrentHashMap<>();

    public ApiKey save(ApiKey entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<ApiKey> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<ApiKey> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(ApiKey::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
