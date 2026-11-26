package com.ledger.budgets;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class BudgetMapper {

    private BudgetMapper() {
    }

    public static BudgetDto toDto(Budget e) {
        return new BudgetDto(e.id(),
                e.name(), e.periodStart(), e.limitCents(),
                e.spentCents());
    }

    public static Budget create(AuthUser user, BudgetDto dto) {
        return new Budget(Ids.next("bud"), user.tenantId(), user.id(),
                Text.required(dto.name(), "name"), dto.periodStart(), dto.limitCents(),
                dto.spentCents());
    }

    public static Budget apply(Budget current, BudgetDto dto) {
        return new Budget(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.name(), "name"), dto.periodStart(), dto.limitCents(),
                dto.spentCents());
    }
}
