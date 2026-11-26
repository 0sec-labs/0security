package com.ledger.reports;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class ReportRepository {

    private final Map<String, Report> store = new ConcurrentHashMap<>();

    public Report save(Report entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<Report> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Report> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Report::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
