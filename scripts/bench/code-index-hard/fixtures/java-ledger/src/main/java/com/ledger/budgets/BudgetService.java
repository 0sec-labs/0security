package com.ledger.budgets;

import com.ledger.common.Access;
import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class BudgetService {

    private final BudgetRepository repository;

    public BudgetService(BudgetRepository repository) {
        this.repository = repository;
    }

    public List<BudgetDto> list(AuthUser user) {
        return repository.listByTenant(user.tenantId()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .map(BudgetMapper::toDto)
                .toList();
    }

    public BudgetDto get(AuthUser user, String id) {
        return BudgetMapper.toDto(owned(user, id));
    }

    public BudgetDto create(AuthUser user, BudgetDto dto) {
        return BudgetMapper.toDto(repository.save(BudgetMapper.create(user, dto)));
    }

    public BudgetDto update(AuthUser user, String id, BudgetDto dto) {
        Budget current = owned(user, id);
        return BudgetMapper.toDto(repository.save(BudgetMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Budget current = owned(user, id);
        repository.removeInTenant(user.tenantId(), current.id());
    }
    public Map<String, Long> remaining(AuthUser user, String id) {
        Budget budget = owned(user, id);
        return Map.of("remainingCents", budget.limitCents() - budget.spentCents());
    }

    private Budget owned(AuthUser user, String id) {
        Budget entity = repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("budgets"));
        Access.requireOwnerOrManager(user, entity.ownerId());
        return entity;
    }
}
