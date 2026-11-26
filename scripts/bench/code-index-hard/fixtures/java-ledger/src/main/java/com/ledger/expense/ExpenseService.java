package com.ledger.expense;

import com.ledger.approval.ApprovalService;
import com.ledger.common.Access;
import com.ledger.common.ConflictException;
import com.ledger.common.NotFoundException;
import com.ledger.project.Project;
import com.ledger.project.ProjectRepository;
import com.ledger.security.AuthUser;
import com.ledger.vendor.VendorRepository;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class ExpenseService {

    private final ExpenseRepository repository;
    private final ExpenseMapper mapper;
    private final ProjectRepository projects;
    private final VendorRepository vendors;
    private final ApprovalService approvals;

    public ExpenseService(ExpenseRepository repository, ExpenseMapper mapper, ProjectRepository projects,
                          VendorRepository vendors, ApprovalService approvals) {
        this.repository = repository;
        this.mapper = mapper;
        this.projects = projects;
        this.vendors = vendors;
        this.approvals = approvals;
    }

    /**
     * Loads an expense the caller may see: same tenant, and either the owner or a manager.
     */
    public Expense get(AuthUser user, String id) {
        Expense expense = repository.findById(id).orElseThrow(() -> new NotFoundException("expense"));
        Access.requireTenant(user, expense.tenantId());
        Access.requireOwnerOrManager(user, expense.ownerId());
        return expense;
    }

    public ExpenseDto view(AuthUser user, String id) {
        return mapper.toDto(get(user, id));
    }

    public List<ExpenseDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .map(mapper::toDto)
                .toList();
    }

    public ExpenseDto create(AuthUser user, ExpenseDto dto) {
        checkReferences(user, dto);
        Expense expense = repository.save(mapper.create(user, dto));
        return mapper.toDto(expense);
    }

    public ExpenseDto update(AuthUser user, String id, ExpenseDto dto) {
        Expense current = get(user, id);
        if (!"DRAFT".equals(current.status())) {
            throw new ConflictException("only drafts can be edited");
        }
        checkReferences(user, dto);
        return mapper.toDto(repository.save(mapper.apply(current, dto)));
    }

    public ExpenseDto submit(AuthUser user, String id) {
        Expense current = get(user, id);
        if (!"DRAFT".equals(current.status())) {
            throw new ConflictException("expense was already submitted");
        }
        Expense submitted = repository.save(current.withStatus("SUBMITTED"));
        approvals.open(user, submitted);
        return mapper.toDto(submitted);
    }

    public void delete(AuthUser user, String id) {
        Expense current = get(user, id);
        if (!"DRAFT".equals(current.status())) {
            throw new ConflictException("only drafts can be deleted");
        }
        repository.delete(current.id());
    }

    private void checkReferences(AuthUser user, ExpenseDto dto) {
        if (dto.projectId() != null) {
            Project project = projects.findById(dto.projectId()).orElseThrow(() -> new NotFoundException("project"));
            Access.requireTenant(user, project.tenantId());
        }
        if (dto.vendorId() != null) {
            vendors.findInTenant(user.tenantId(), dto.vendorId()).orElseThrow(() -> new NotFoundException("vendor"));
        }
    }
}
