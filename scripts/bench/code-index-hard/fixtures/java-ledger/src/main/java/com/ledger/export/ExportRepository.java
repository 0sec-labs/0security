package com.ledger.export;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class ExportRepository {

    private final Map<String, ExportJob> store = new ConcurrentHashMap<>();

    public ExportJob save(ExportJob job) {
        store.put(job.id(), job);
        return job;
    }

    public Optional<ExportJob> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<ExportJob> findByOwner(String tenantId, String ownerId) {
        return store.values().stream()
                .filter(j -> j.tenantId().equals(tenantId) && j.ownerId().equals(ownerId))
                .sorted(Comparator.comparing(ExportJob::id))
                .toList();
    }
}
