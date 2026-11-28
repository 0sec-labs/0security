package com.ledger.tags;

import com.ledger.common.Access;
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

/**
 * Everyone in the tenant can read these records; changes are limited to the owner or a manager.
 */
@RestController
@RequestMapping("/api/tags")
public class TagController {

    private final TagService service;

    public TagController(TagService service) {
        this.service = service;
    }

    @GetMapping
    public List<TagDto> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public TagDto get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.view(user, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public TagDto create(@AuthenticationPrincipal AuthUser user, @RequestBody TagDto dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")
    public TagDto update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody TagDto dto) {
        Tag current = service.find(user, id);
        Access.requireOwnerOrManager(user, current.ownerId());
        return service.update(current, dto);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        Tag current = service.find(user, id);
        Access.requireOwnerOrManager(user, current.ownerId());
        service.remove(current);
    }

    @PostMapping("/{id}/attach/{expenseId}")
    public Map<String, Integer> attach(@AuthenticationPrincipal AuthUser user, @PathVariable String id,
                                       @PathVariable String expenseId) {
        Tag tag = service.find(user, id);
        Access.requireOwnerOrManager(user, tag.ownerId());
        return Map.of("attached", service.attach(user, tag, expenseId));
    }
}
