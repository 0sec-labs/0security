package com.ledger.preferences;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class PreferenceRepository {

    private final Map<String, Preference> store = new ConcurrentHashMap<>();

    public Preference save(Preference entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<Preference> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Preference> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Preference::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
