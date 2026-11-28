package com.ledger.expense;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;
import org.springframework.stereotype.Component;

@Component
public class ExpenseMapper {

    public ExpenseDto toDto(Expense e) {
        return new ExpenseDto(e.id(), e.projectId(), e.vendorId(), e.description(), e.amountCents(), e.currency(),
                e.status(), e.incurredOn());
    }

    public Expense create(AuthUser user, ExpenseDto dto) {
        return new Expense(Ids.next("ex"), user.tenantId(), user.id(), dto.projectId(), dto.vendorId(),
                Text.required(dto.description(), "description"), dto.amountCents(),
                dto.currency() == null ? "EUR" : dto.currency(), "DRAFT", dto.incurredOn());
    }

    public Expense apply(Expense current, ExpenseDto dto) {
        return new Expense(current.id(), current.tenantId(), current.ownerId(), dto.projectId(), dto.vendorId(),
                Text.required(dto.description(), "description"), dto.amountCents(),
                dto.currency() == null ? current.currency() : dto.currency(), current.status(), dto.incurredOn());
    }
}
