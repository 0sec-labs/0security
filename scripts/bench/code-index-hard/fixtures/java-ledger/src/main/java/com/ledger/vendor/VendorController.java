package com.ledger.vendor;

import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
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
@RequestMapping("/api/tenants/{tenantId}/vendors")
public class VendorController {

    private final VendorService service;

    public VendorController(VendorService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("@access.canManage(#tenantId)")
    public List<VendorDto> list(@PathVariable String tenantId) {
        return service.list(tenantId);
    }

    @GetMapping("/{id}")
    @PreAuthorize("@access.canManage(#tenantId)")
    public VendorDto get(@PathVariable String tenantId, @PathVariable String id) {
        return service.get(tenantId, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("@access.canManage(#tenantId)")
    public VendorDto create(@PathVariable String tenantId, @RequestBody VendorDto dto) {
        return service.create(tenantId, dto);
    }

    @PutMapping("/{id}")
    @PreAuthorize("@access.canManage(#tenantId)")
    public VendorDto update(@PathVariable String tenantId, @PathVariable String id, @RequestBody VendorDto dto) {
        return service.update(tenantId, id, dto);
    }

    @PostMapping("/{id}/archive")
    @PreAuthorize("@access.canManage(#tenantId)")
    public VendorDto archive(@PathVariable String tenantId, @PathVariable String id) {
        return service.setStatus(tenantId, id, "ARCHIVED");
    }

    @PostMapping("/{id}/restore")
    @PreAuthorize("@access.canManage(#tenantId)")
    public VendorDto restore(@PathVariable String tenantId, @PathVariable String id) {
        return service.setStatus(tenantId, id, "ACTIVE");
    }

    @GetMapping("/{id}/contacts")
    @PreAuthorize("@access.canManage(#tenantId)")
    public List<VendorContact> contacts(@PathVariable String tenantId, @PathVariable String id) {
        return service.contacts(tenantId, id);
    }

    @PostMapping("/{id}/contacts")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("@access.canManage(#tenantId)")
    public VendorContact addContact(@PathVariable String tenantId, @PathVariable String id, @RequestBody VendorContact contact) {
        return service.addContact(tenantId, id, contact);
    }

    @GetMapping("/{id}/bank-details")
    @PreAuthorize("@access.canManage(#tenantId)")
    public BankDetailsDto bankDetails(@PathVariable String tenantId, @PathVariable String id) {
        return service.bankDetails(tenantId, id);
    }

    @PutMapping("/{id}/bank-details")
    public BankDetailsDto replaceBankDetails(@AuthenticationPrincipal AuthUser user, @PathVariable String tenantId,
                                             @PathVariable String id, @RequestBody BankDetailsDto details) {
        return service.replaceBankDetails(tenantId, id, details, user.id());
    }
}
