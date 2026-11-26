package com.ledger.notes;

import com.ledger.common.Access;
import com.ledger.common.NotFoundException;
import com.ledger.expense.ExpenseService;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class NoteService {

    private final NoteRepository repository;
    private final NoteMapper mapper;
    private final ExpenseService expenses;

    public NoteService(NoteRepository repository, NoteMapper mapper, ExpenseService expenses) {
        this.repository = repository;
        this.mapper = mapper;
        this.expenses = expenses;
    }

    public List<NoteDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .map(mapper::toDto)
                .toList();
    }

    public NoteDto get(AuthUser user, String id) {
        return mapper.toDto(require(user, id));
    }

    public NoteDto create(AuthUser user, NoteDto dto) {
        validate(user, dto);
        return mapper.toDto(repository.save(mapper.create(user, dto)));
    }

    public NoteDto update(AuthUser user, String id, NoteDto dto) {
        Note current = require(user, id);
        validate(user, dto);
        return mapper.toDto(repository.save(mapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Note current = require(user, id);
        repository.delete(current.id());
    }

    private Note require(AuthUser user, String id) {
        Note entity = repository.findById(id).orElseThrow(() -> new NotFoundException("notes"));
        Access.requireTenant(user, entity.tenantId());
        Access.requireOwnerOrManager(user, entity.ownerId());
        return entity;
    }

    private void validate(AuthUser user, NoteDto dto) {
        if (dto.linkedExpenseId() != null) {
            expenses.get(user, dto.linkedExpenseId());
        }
    }
}
