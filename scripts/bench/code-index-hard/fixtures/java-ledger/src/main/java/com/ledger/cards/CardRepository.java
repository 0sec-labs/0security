package com.ledger.cards;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class CardRepository {

    private final Map<String, Card> store = new ConcurrentHashMap<>();

    public Card save(Card entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<Card> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Card> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Card::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
