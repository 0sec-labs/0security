package com.ledger.webhooks;

import com.ledger.security.AuthUser;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
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
@RequestMapping("/api/webhooks")
@PreAuthorize("@access.isManager()")
public class WebhookController {

    private final WebhookService service;

    public WebhookController(WebhookService service) {
        this.service = service;
    }

    @GetMapping
    public List<WebhookDto> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public WebhookDto get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.get(user, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public WebhookDto create(@AuthenticationPrincipal AuthUser user, @RequestBody WebhookDto dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")
    public WebhookDto update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody WebhookDto dto) {
        return service.update(user, id, dto);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        service.delete(user, id);
    }

    @PostMapping("/{id}/ping")
    public Map<String, Object> ping(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.ping(user, id);
    }
}
