package com.ledger.expense;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class ExpenseRepository {

    private final Map<String, Expense> store = new ConcurrentHashMap<>();

    public Expense save(Expense expense) {
        store.put(expense.id(), expense);
        return expense;
    }

    public Optional<Expense> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Expense> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Expense::id))
                .toList();
    }

    public List<Expense> searchByTenant(String tenantId, String query) {
        String needle = query.toLowerCase();
        return findByTenant(tenantId).stream()
                .filter(e -> e.description().toLowerCase().contains(needle))
                .toList();
    }

    public List<Expense> findByProject(String projectId) {
        return store.values().stream()
                .filter(e -> projectId.equals(e.projectId()))
                .sorted(Comparator.comparing(Expense::id))
                .toList();
    }

    public int reassign(String fromProjectId, String toProjectId) {
        List<Expense> moved = new ArrayList<>(findByProject(fromProjectId));
        moved.forEach(e -> store.put(e.id(), e.withProject(toProjectId)));
        return moved.size();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
