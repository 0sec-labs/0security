package com.ledger.notes;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class NoteRepository {

    private final Map<String, Note> store = new ConcurrentHashMap<>();

    public Note save(Note entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<Note> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Note> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Note::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
