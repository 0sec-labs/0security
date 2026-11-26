package com.ledger.purchaseorders;

import com.ledger.common.Access;
import com.ledger.common.ConflictException;
import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import com.ledger.vendor.VendorRepository;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class PurchaseOrderService {

    private final PurchaseOrderRepository repository;
    private final PurchaseOrderMapper mapper;
    private final VendorRepository vendors;

    public PurchaseOrderService(PurchaseOrderRepository repository, PurchaseOrderMapper mapper, VendorRepository vendors) {
        this.repository = repository;
        this.mapper = mapper;
        this.vendors = vendors;
    }

    public List<PurchaseOrderDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .map(mapper::toDto)
                .toList();
    }

    public PurchaseOrderDto get(AuthUser user, String id) {
        return mapper.toDto(require(user, id));
    }

    public PurchaseOrderDto create(AuthUser user, PurchaseOrderDto dto) {
        validate(user, dto);
        return mapper.toDto(repository.save(mapper.create(user, dto)));
    }

    public PurchaseOrderDto update(AuthUser user, String id, PurchaseOrderDto dto) {
        PurchaseOrder current = require(user, id);
        validate(user, dto);
        return mapper.toDto(repository.save(mapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        PurchaseOrder current = require(user, id);
        repository.delete(current.id());
    }
    public PurchaseOrderDto receive(AuthUser user, String id) {
        PurchaseOrder current = require(user, id);
        if (!"OPEN".equals(current.status())) {
            throw new ConflictException("order is not open");
        }
        PurchaseOrder next = new PurchaseOrder(current.id(), current.tenantId(), current.ownerId(), current.number(),
                current.vendorRef(), current.totalCents(), "RECEIVED");
        return mapper.toDto(repository.save(next));
    }

    private PurchaseOrder require(AuthUser user, String id) {
        PurchaseOrder entity = repository.findById(id).orElseThrow(() -> new NotFoundException("purchase-orders"));
        Access.requireTenant(user, entity.tenantId());
        Access.requireOwnerOrManager(user, entity.ownerId());
        return entity;
    }

    private void validate(AuthUser user, PurchaseOrderDto dto) {
        if (dto.vendorRef() != null) {
            vendors.findInTenant(user.tenantId(), dto.vendorRef()).orElseThrow(() -> new NotFoundException("vendor"));
        }
    }
}
