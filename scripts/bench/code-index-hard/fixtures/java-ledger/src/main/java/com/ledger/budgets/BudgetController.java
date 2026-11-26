package com.ledger.budgets;

import com.ledger.security.AuthUser;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/budgets")
public class BudgetController {

    private final BudgetService service;

    public BudgetController(BudgetService service) {
        this.service = service;
    }

    @GetMapping
    public List<BudgetDto> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public BudgetDto get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.get(user, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public BudgetDto create(@AuthenticationPrincipal AuthUser user, @RequestBody BudgetDto dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")
    public BudgetDto update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody BudgetDto dto) {
        return service.update(user, id, dto);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        service.delete(user, id);
    }

    @GetMapping("/{id}/remaining")
    public Map<String, Long> remaining(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.remaining(user, id);
    }
}
