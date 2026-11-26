package com.ledger.approval;

import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/approvals")
@PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
public class ApprovalController {

    private final ApprovalService service;

    public ApprovalController(ApprovalService service) {
        this.service = service;
    }

    @GetMapping
    public List<Approval> pending(@AuthenticationPrincipal AuthUser user) {
        return service.pending(user);
    }

    @PostMapping("/{id}/approve")
    public Approval approve(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.approve(user, id);
    }

    @PostMapping("/{id}/reject")
    public Approval reject(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.reject(user, id);
    }

    @PostMapping("/bulk-approve")
    public List<Approval> bulkApprove(@AuthenticationPrincipal AuthUser user, @RequestBody BulkApprovalRequest request) {
        return service.approveAll(user, request);
    }
}
