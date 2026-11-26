package com.ledger.reports;

import com.ledger.common.Access;
import com.ledger.common.NotFoundException;
import com.ledger.expense.ExpenseRepository;
import com.ledger.security.AuthUser;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class ReportService {

    private final ReportRepository repository;
    private final ReportMapper mapper;
    private final ExpenseRepository expenses;

    public ReportService(ReportRepository repository, ReportMapper mapper, ExpenseRepository expenses) {
        this.repository = repository;
        this.mapper = mapper;
        this.expenses = expenses;
    }

    public List<ReportDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .map(mapper::toDto)
                .toList();
    }

    public ReportDto get(AuthUser user, String id) {
        return mapper.toDto(require(user, id));
    }

    public ReportDto create(AuthUser user, ReportDto dto) {
        return mapper.toDto(repository.save(mapper.create(user, dto)));
    }

    public ReportDto update(AuthUser user, String id, ReportDto dto) {
        Report current = require(user, id);
        return mapper.toDto(repository.save(mapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Report current = require(user, id);
        repository.delete(current.id());
    }
    public Map<String, Integer> run(AuthUser user, String id) {
        require(user, id);
        long rows = expenses.findByTenant(user.tenantId()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .count();
        return Map.of("rows", (int) rows);
    }

    private Report require(AuthUser user, String id) {
        Report entity = repository.findById(id).orElseThrow(() -> new NotFoundException("reports"));
        Access.requireTenant(user, entity.tenantId());
        Access.requireOwnerOrManager(user, entity.ownerId());
        return entity;
    }
}
