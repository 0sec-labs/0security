package com.ledger.templates;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class TemplateRepository {

    private final Map<String, Template> store = new ConcurrentHashMap<>();

    public Template save(Template entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<Template> findByTenantAndId(String tenantId, String id) {
        return Optional.ofNullable(store.get(id)).filter(e -> e.tenantId().equals(tenantId));
    }

    public List<Template> listByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Template::id))
                .toList();
    }

    public void removeInTenant(String tenantId, String id) {
        findByTenantAndId(tenantId, id).ifPresent(e -> store.remove(e.id()));
    }
}
