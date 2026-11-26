package com.ledger.tags;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class TagRepository {

    private final Map<String, Tag> store = new ConcurrentHashMap<>();

    public Tag save(Tag entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<Tag> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Tag> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Tag::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }

    private final Map<String, Set<String>> attachments = new ConcurrentHashMap<>();

    public void attach(String tagId, String expenseId) {
        attachments.computeIfAbsent(tagId, k -> ConcurrentHashMap.newKeySet()).add(expenseId);
    }

    public Set<String> attachedTo(String tagId) {
        return attachments.getOrDefault(tagId, Set.of());
    }
}
