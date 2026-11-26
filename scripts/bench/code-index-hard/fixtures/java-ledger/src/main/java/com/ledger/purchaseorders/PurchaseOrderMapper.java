package com.ledger.purchaseorders;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;
import org.springframework.stereotype.Component;

@Component
public class PurchaseOrderMapper {

    public PurchaseOrderDto toDto(PurchaseOrder e) {
        return new PurchaseOrderDto(e.id(),
                e.number(), e.vendorRef(), e.totalCents(),
                e.status());
    }

    public PurchaseOrder create(AuthUser user, PurchaseOrderDto dto) {
        return new PurchaseOrder(Ids.next("po"), user.tenantId(), user.id(),
                Text.required(dto.number(), "number"), dto.vendorRef(), dto.totalCents(),
                dto.status());
    }

    public PurchaseOrder apply(PurchaseOrder current, PurchaseOrderDto dto) {
        return new PurchaseOrder(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.number(), "number"), dto.vendorRef(), dto.totalCents(),
                dto.status());
    }
}
