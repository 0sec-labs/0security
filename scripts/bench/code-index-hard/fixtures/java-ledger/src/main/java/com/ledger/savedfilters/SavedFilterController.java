package com.ledger.savedfilters;

import com.ledger.expense.ExpenseDto;
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
@RequestMapping("/api/saved-filters")
public class SavedFilterController {

    private final SavedFilterService service;

    public SavedFilterController(SavedFilterService service) {
        this.service = service;
    }

    @GetMapping
    public List<SavedFilterDto> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public SavedFilterDto get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.get(user, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public SavedFilterDto create(@AuthenticationPrincipal AuthUser user, @RequestBody SavedFilterDto dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")
    public SavedFilterDto update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody SavedFilterDto dto) {
        return service.update(user, id, dto);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        service.delete(user, id);
    }

    @GetMapping("/{id}/apply")
    public List<ExpenseDto> apply(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.apply(user, id);
    }
}
