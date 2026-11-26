package com.ledger.mileage;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class MileageEntryRepository {

    private final Map<String, MileageEntry> store = new ConcurrentHashMap<>();

    public MileageEntry save(MileageEntry entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<MileageEntry> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<MileageEntry> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(MileageEntry::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
