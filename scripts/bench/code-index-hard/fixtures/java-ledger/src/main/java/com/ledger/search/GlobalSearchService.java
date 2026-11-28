package com.ledger.search;

import com.ledger.comment.CommentRepository;
import com.ledger.common.BadRequestException;
import com.ledger.expense.ExpenseRepository;
import com.ledger.security.AuthUser;
import com.ledger.vendor.VendorRepository;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class GlobalSearchService {

    private final ExpenseRepository expenses;
    private final VendorRepository vendors;
    private final CommentRepository comments;

    public GlobalSearchService(ExpenseRepository expenses, VendorRepository vendors, CommentRepository comments) {
        this.expenses = expenses;
        this.vendors = vendors;
        this.comments = comments;
    }

    public List<SearchHit> search(AuthUser user, String query) {
        if (query == null || query.strip().length() < 3) {
            throw new BadRequestException("query is too short");
        }
        String q = query.strip();
        List<SearchHit> hits = new ArrayList<>();
        expenses.searchByTenant(user.tenantId(), q).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .forEach(e -> hits.add(new SearchHit("expense", e.id(), e.description())));
        if (user.isManager()) {
            vendors.search(user.tenantId(), q).forEach(v -> hits.add(new SearchHit("vendor", v.id(), v.name())));
        }
        comments.search(q).forEach(c -> hits.add(new SearchHit("comment", c.id(), c.body())));
        return hits;
    }
}
