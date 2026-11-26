package com.ledger.expense;

import com.ledger.security.AuthUser;
import java.util.List;
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
@RequestMapping("/api/expenses")
public class ExpenseController {

    private final ExpenseService service;

    public ExpenseController(ExpenseService service) {
        this.service = service;
    }

    @GetMapping
    public List<ExpenseDto> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public ExpenseDto get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.view(user, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ExpenseDto create(@AuthenticationPrincipal AuthUser user, @RequestBody ExpenseDto dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")
    public ExpenseDto update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody ExpenseDto dto) {
        return service.update(user, id, dto);
    }

    @PostMapping("/{id}/submit")
    public ExpenseDto submit(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.submit(user, id);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        service.delete(user, id);
    }
}
