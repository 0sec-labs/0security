package com.ledger.comment;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class CommentRepository {

    private final Map<String, Comment> store = new ConcurrentHashMap<>();

    public Comment save(Comment comment) {
        store.put(comment.id(), comment);
        return comment;
    }

    public Optional<Comment> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Comment> findByExpense(String expenseId) {
        return store.values().stream()
                .filter(c -> c.expenseId().equals(expenseId))
                .sorted(Comparator.comparing(Comment::id))
                .toList();
    }

    public List<Comment> search(String query) {
        String needle = query.toLowerCase();
        return store.values().stream()
                .filter(c -> c.body().toLowerCase().contains(needle))
                .sorted(Comparator.comparing(Comment::id))
                .toList();
    }
}
