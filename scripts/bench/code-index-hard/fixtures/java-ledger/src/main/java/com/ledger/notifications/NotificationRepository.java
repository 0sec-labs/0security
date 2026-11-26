package com.ledger.notifications;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class NotificationRepository {

    private final Map<String, Notification> store = new ConcurrentHashMap<>();

    public Notification save(Notification entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<Notification> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Notification> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Notification::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
