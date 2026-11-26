package com.ledger.assets;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class AssetRepository {

    private final Map<String, Asset> store = new ConcurrentHashMap<>();

    public Asset save(Asset entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<Asset> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Asset> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Asset::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
