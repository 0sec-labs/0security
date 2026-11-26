package com.ledger.vendor;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import org.springframework.stereotype.Component;

@Component
public class VendorMapper {

    public VendorDto toDto(Vendor v) {
        return new VendorDto(v.id(), v.name(), v.category(), v.taxId(), v.status());
    }

    public Vendor create(String tenantId, VendorDto dto) {
        return new Vendor(Ids.next("ven"), tenantId, Text.required(dto.name(), "name"), Text.plain(dto.category()),
                Text.plain(dto.taxId()), "ACTIVE", null);
    }

    public Vendor apply(Vendor current, VendorDto dto) {
        return new Vendor(current.id(), current.tenantId(), Text.required(dto.name(), "name"), Text.plain(dto.category()),
                Text.plain(dto.taxId()), current.status(), current.bank());
    }
}
