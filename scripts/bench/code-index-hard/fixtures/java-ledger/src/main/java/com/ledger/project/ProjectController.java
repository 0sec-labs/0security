package com.ledger.project;

import com.ledger.expense.ExpenseDto;
import com.ledger.security.AuthUser;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/projects")
public class ProjectController {

    private final ProjectService service;

    public ProjectController(ProjectService service) {
        this.service = service;
    }

    @GetMapping
    public List<ProjectDto> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public ProjectDto get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.get(user, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ProjectDto create(@AuthenticationPrincipal AuthUser user, @RequestBody ProjectDto dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")
    public ProjectDto update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody ProjectDto dto) {
        return service.update(user, id, dto);
    }

    @GetMapping("/{id}/expenses")
    public List<ExpenseDto> expenses(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.expensesOf(user, id);
    }

    @PostMapping("/{id}/transfer-expenses")
    public Map<String, Integer> transferExpenses(@AuthenticationPrincipal AuthUser user, @PathVariable String id,
                                                 @RequestBody TransferRequest request) {
        return Map.of("moved", service.transferExpenses(user, id, request.targetProjectId()));
    }
}
