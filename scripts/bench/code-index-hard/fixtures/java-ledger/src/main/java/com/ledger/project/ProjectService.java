package com.ledger.project;

import com.ledger.common.Access;
import com.ledger.common.BadRequestException;
import com.ledger.common.ForbiddenException;
import com.ledger.common.Ids;
import com.ledger.common.NotFoundException;
import com.ledger.common.Text;
import com.ledger.expense.ExpenseDto;
import com.ledger.expense.ExpenseRepository;
import com.ledger.security.AuthUser;
import com.ledger.security.Role;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class ProjectService {

    private final ProjectRepository repository;
    private final ExpenseRepository expenses;

    public ProjectService(ProjectRepository repository, ExpenseRepository expenses) {
        this.repository = repository;
        this.expenses = expenses;
    }

    public List<ProjectDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream().map(this::toDto).toList();
    }

    public ProjectDto get(AuthUser user, String id) {
        return toDto(requireInTenant(user, id));
    }

    public ProjectDto create(AuthUser user, ProjectDto dto) {
        Access.requireManager(user);
        Project project = new Project(Ids.next("pr"), user.tenantId(), Text.required(dto.name(), "name"), user.id(), "ACTIVE");
        return toDto(repository.save(project));
    }

    public ProjectDto update(AuthUser user, String id, ProjectDto dto) {
        Project current = requireManaged(user, id);
        return toDto(repository.save(new Project(current.id(), current.tenantId(), Text.required(dto.name(), "name"),
                current.managerId(), dto.status() == null ? current.status() : dto.status())));
    }

    public List<ExpenseDto> expensesOf(AuthUser user, String id) {
        Project project = requireInTenant(user, id);
        return expenses.findByProject(project.id()).stream()
                .map(e -> new ExpenseDto(e.id(), e.projectId(), e.vendorId(), e.description(), e.amountCents(),
                        e.currency(), e.status(), e.incurredOn()))
                .toList();
    }

    /**
     * Moves every expense of a project to another project and returns how many were moved.
     */
    public int transferExpenses(AuthUser user, String sourceId, String targetId) {
        Project source = requireManaged(user, sourceId);
        Project target = repository.findById(targetId).orElseThrow(() -> new NotFoundException("project"));
        if (source.id().equals(target.id())) {
            throw new BadRequestException("source and target are the same project");
        }
        return expenses.reassign(source.id(), target.id());
    }

    private Project requireInTenant(AuthUser user, String id) {
        Project project = repository.findById(id).orElseThrow(() -> new NotFoundException("project"));
        Access.requireTenant(user, project.tenantId());
        return project;
    }

    private Project requireManaged(AuthUser user, String id) {
        Project project = requireInTenant(user, id);
        if (!project.managerId().equals(user.id()) && user.role() != Role.ADMIN) {
            throw new ForbiddenException("only the project manager can do this");
        }
        return project;
    }

    private ProjectDto toDto(Project p) {
        return new ProjectDto(p.id(), p.name(), p.managerId(), p.status());
    }
}
