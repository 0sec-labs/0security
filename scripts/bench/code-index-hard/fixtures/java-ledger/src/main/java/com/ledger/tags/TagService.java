package com.ledger.tags;

import com.ledger.common.NotFoundException;
import com.ledger.expense.ExpenseService;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class TagService {

    private final TagRepository repository;
    private final TagMapper mapper;
    private final ExpenseService expenses;

    public TagService(TagRepository repository, TagMapper mapper, ExpenseService expenses) {
        this.repository = repository;
        this.mapper = mapper;
        this.expenses = expenses;
    }

    public List<TagDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .map(mapper::toDto)
                .toList();
    }

    public Tag find(AuthUser user, String id) {
        return repository.findById(id)
                .filter(e -> e.tenantId().equals(user.tenantId()))
                .orElseThrow(() -> new NotFoundException("tags"));
    }

    public TagDto view(AuthUser user, String id) {
        return mapper.toDto(find(user, id));
    }

    public TagDto create(AuthUser user, TagDto dto) {
        return mapper.toDto(repository.save(mapper.create(user, dto)));
    }

    public TagDto update(Tag current, TagDto dto) {
        return mapper.toDto(repository.save(mapper.apply(current, dto)));
    }

    public void remove(Tag current) {
        repository.delete(current.id());
    }
    public int attach(AuthUser user, Tag tag, String expenseId) {
        expenses.get(user, expenseId);
        repository.attach(tag.id(), expenseId);
        return repository.attachedTo(tag.id()).size();
    }
}
