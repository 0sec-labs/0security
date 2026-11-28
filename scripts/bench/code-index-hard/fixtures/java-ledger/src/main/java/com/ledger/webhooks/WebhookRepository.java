package com.ledger.webhooks;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class WebhookRepository {

    private final Map<String, Webhook> store = new ConcurrentHashMap<>();

    public Webhook save(Webhook entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<Webhook> findByTenantAndId(String tenantId, String id) {
        return Optional.ofNullable(store.get(id)).filter(e -> e.tenantId().equals(tenantId));
    }

    public List<Webhook> listByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Webhook::id))
                .toList();
    }

    public void removeInTenant(String tenantId, String id) {
        findByTenantAndId(tenantId, id).ifPresent(e -> store.remove(e.id()));
    }
}
