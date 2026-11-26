package com.ledger.purchaseorders;

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
@RequestMapping("/api/purchase-orders")
public class PurchaseOrderController {

    private final PurchaseOrderService service;

    public PurchaseOrderController(PurchaseOrderService service) {
        this.service = service;
    }

    @GetMapping
    public List<PurchaseOrderDto> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public PurchaseOrderDto get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.get(user, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public PurchaseOrderDto create(@AuthenticationPrincipal AuthUser user, @RequestBody PurchaseOrderDto dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")
    public PurchaseOrderDto update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody PurchaseOrderDto dto) {
        return service.update(user, id, dto);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        service.delete(user, id);
    }

    @PostMapping("/{id}/receive")
    public PurchaseOrderDto receive(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.receive(user, id);
    }
}
