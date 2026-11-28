package com.ledger.comment;

import com.ledger.expense.ExpenseService;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/expenses/{expenseId}/comments")
public class CommentController {

    private final CommentService service;
    private final ExpenseService expenses;

    public CommentController(CommentService service, ExpenseService expenses) {
        this.service = service;
        this.expenses = expenses;
    }

    @GetMapping
    public List<Comment> list(@AuthenticationPrincipal AuthUser user, @PathVariable String expenseId) {
        return service.list(user, expenseId);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Comment add(@AuthenticationPrincipal AuthUser user, @PathVariable String expenseId, @RequestBody CommentInput input) {
        expenses.get(user, expenseId);
        return service.add(input.forExpense(user.tenantId(), expenseId));
    }
}
