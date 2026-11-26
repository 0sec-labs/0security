package com.ledger.savedfilters;

import com.ledger.common.Access;
import com.ledger.common.NotFoundException;
import com.ledger.expense.ExpenseDto;
import com.ledger.expense.ExpenseMapper;
import com.ledger.expense.ExpenseRepository;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class SavedFilterService {

    private final SavedFilterRepository repository;
    private final ExpenseRepository expenses;
    private final ExpenseMapper expenseMapper;

    public SavedFilterService(SavedFilterRepository repository, ExpenseRepository expenses, ExpenseMapper expenseMapper) {
        this.repository = repository;
        this.expenses = expenses;
        this.expenseMapper = expenseMapper;
    }

    public List<SavedFilterDto> list(AuthUser user) {
        return repository.listByTenant(user.tenantId()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .map(SavedFilterMapper::toDto)
                .toList();
    }

    public SavedFilterDto get(AuthUser user, String id) {
        return SavedFilterMapper.toDto(owned(user, id));
    }

    public SavedFilterDto create(AuthUser user, SavedFilterDto dto) {
        return SavedFilterMapper.toDto(repository.save(SavedFilterMapper.create(user, dto)));
    }

    public SavedFilterDto update(AuthUser user, String id, SavedFilterDto dto) {
        SavedFilter current = owned(user, id);
        return SavedFilterMapper.toDto(repository.save(SavedFilterMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        SavedFilter current = owned(user, id);
        repository.removeInTenant(user.tenantId(), current.id());
    }
    public List<ExpenseDto> apply(AuthUser user, String id) {
        SavedFilter filter = owned(user, id);
        return expenses.searchByTenant(user.tenantId(), filter.query()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .map(expenseMapper::toDto)
                .toList();
    }

    private SavedFilter owned(AuthUser user, String id) {
        SavedFilter entity = repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("saved-filters"));
        Access.requireOwnerOrManager(user, entity.ownerId());
        return entity;
    }
}
