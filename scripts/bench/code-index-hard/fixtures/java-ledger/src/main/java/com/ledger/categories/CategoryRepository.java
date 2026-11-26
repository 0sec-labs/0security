package com.ledger.categories;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class CategoryRepository {

    private final Map<String, Category> store = new ConcurrentHashMap<>();

    public Category save(Category entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<Category> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Category> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Category::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
