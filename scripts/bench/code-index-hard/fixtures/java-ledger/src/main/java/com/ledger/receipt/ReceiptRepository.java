package com.ledger.receipt;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class ReceiptRepository {

    private final Map<String, Receipt> store = new ConcurrentHashMap<>();

    public Receipt save(Receipt receipt) {
        store.put(receipt.id(), receipt);
        return receipt;
    }

    public Optional<Receipt> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Receipt> findByExpense(String expenseId) {
        return store.values().stream()
                .filter(r -> r.expenseId().equals(expenseId))
                .sorted(Comparator.comparing(Receipt::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
