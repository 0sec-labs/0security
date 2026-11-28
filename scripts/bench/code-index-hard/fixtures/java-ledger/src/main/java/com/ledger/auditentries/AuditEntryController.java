package com.ledger.auditentries;

import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/audit-entries")
@PreAuthorize("@access.isManager()")
public class AuditEntryController {

    private final AuditEntryService service;

    public AuditEntryController(AuditEntryService service) {
        this.service = service;
    }

    @GetMapping
    public List<AuditEntryDto> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public AuditEntryDto get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.get(user, id);
    }
}
