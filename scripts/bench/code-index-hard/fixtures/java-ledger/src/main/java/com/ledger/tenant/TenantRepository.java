package com.ledger.tenant;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class TenantRepository {

    private final Map<String, Tenant> store = new ConcurrentHashMap<>();

    public Tenant save(Tenant tenant) {
        store.put(tenant.id(), tenant);
        return tenant;
    }

    public Optional<Tenant> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Tenant> findAll() {
        return store.values().stream().sorted(Comparator.comparing(Tenant::id)).toList();
    }
}
