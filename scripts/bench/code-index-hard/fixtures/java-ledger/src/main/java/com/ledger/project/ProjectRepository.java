package com.ledger.project;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class ProjectRepository {

    private final Map<String, Project> store = new ConcurrentHashMap<>();

    public Project save(Project project) {
        store.put(project.id(), project);
        return project;
    }

    public Optional<Project> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Project> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(p -> p.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Project::id))
                .toList();
    }
}
