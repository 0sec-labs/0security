package com.ledger.purchaseorders;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class PurchaseOrderRepository {

    private final Map<String, PurchaseOrder> store = new ConcurrentHashMap<>();

    public PurchaseOrder save(PurchaseOrder entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<PurchaseOrder> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<PurchaseOrder> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(PurchaseOrder::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
