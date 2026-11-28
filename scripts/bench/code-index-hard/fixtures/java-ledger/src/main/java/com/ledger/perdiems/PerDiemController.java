package com.ledger.perdiems;

import com.ledger.common.Access;
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

/**
 * Everyone in the tenant can read these records; changes are limited to the owner or a manager.
 */
@RestController
@RequestMapping("/api/per-diems")
public class PerDiemController {

    private final PerDiemService service;

    public PerDiemController(PerDiemService service) {
        this.service = service;
    }

    @GetMapping
    public List<PerDiemDto> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public PerDiemDto get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.view(user, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public PerDiemDto create(@AuthenticationPrincipal AuthUser user, @RequestBody PerDiemDto dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")
    public PerDiemDto update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody PerDiemDto dto) {
        PerDiem current = service.find(user, id);
        Access.requireOwnerOrManager(user, current.ownerId());
        return service.update(current, dto);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        PerDiem current = service.find(user, id);
        Access.requireOwnerOrManager(user, current.ownerId());
        service.remove(current);
    }
}
