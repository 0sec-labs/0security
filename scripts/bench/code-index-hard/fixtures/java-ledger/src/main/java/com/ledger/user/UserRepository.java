package com.ledger.user;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {

    private final Map<String, User> store = new ConcurrentHashMap<>();

    public User save(User user) {
        store.put(user.id(), user);
        return user;
    }

    public Optional<User> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<User> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(u -> u.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(User::id))
                .toList();
    }
}
