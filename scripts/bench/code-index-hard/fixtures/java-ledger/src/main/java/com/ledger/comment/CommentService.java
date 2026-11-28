package com.ledger.comment;

import com.ledger.common.BadRequestException;
import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.expense.ExpenseService;
import com.ledger.security.AuthUser;
import java.time.Instant;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class CommentService {

    private final CommentRepository repository;
    private final ExpenseService expenses;

    public CommentService(CommentRepository repository, ExpenseService expenses) {
        this.repository = repository;
        this.expenses = expenses;
    }

    public List<Comment> list(AuthUser user, String expenseId) {
        expenses.get(user, expenseId);
        return repository.findByExpense(expenseId);
    }

    public Comment add(CommentInput input) {
        String body = Text.plain(input.body());
        if (body.isEmpty()) {
            throw new BadRequestException("body is required");
        }
        return repository.save(new Comment(Ids.next("cmt"), input.tenantId(), input.expenseId(), input.authorId(), body,
                Instant.now()));
    }
}
