package com.ledger.costcenters;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class CostCenterMapper {

    private CostCenterMapper() {
    }

    public static CostCenterDto toDto(CostCenter e) {
        return new CostCenterDto(e.id(),
                e.code(), e.name(), e.parentCode());
    }

    public static CostCenter create(AuthUser user, CostCenterDto dto) {
        return new CostCenter(Ids.next("cc"), user.tenantId(), user.id(),
                Text.required(dto.code(), "code"), Text.plain(dto.name()), dto.parentCode());
    }

    public static CostCenter apply(CostCenter current, CostCenterDto dto) {
        return new CostCenter(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.code(), "code"), Text.plain(dto.name()), dto.parentCode());
    }
}
