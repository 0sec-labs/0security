package com.ledger.statement;

import com.ledger.security.AuthUser;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/statements")
public class StatementController {

    private final StatementService service;

    public StatementController(StatementService service) {
        this.service = service;
    }

    @GetMapping
    public List<StatementView> mine(@AuthenticationPrincipal AuthUser user) {
        return service.mine(user);
    }

    @GetMapping("/{id}")
    public StatementView get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.buildFor(user, id);
    }

    @PostMapping("/{id}/share")
    public Map<String, String> share(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return Map.of("token", service.share(user, id));
    }
}
