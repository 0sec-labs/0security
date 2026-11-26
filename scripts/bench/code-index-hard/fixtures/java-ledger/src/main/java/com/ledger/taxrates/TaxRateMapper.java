package com.ledger.taxrates;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class TaxRateMapper {

    private TaxRateMapper() {
    }

    public static TaxRateDto toDto(TaxRate e) {
        return new TaxRateDto(e.id(),
                e.name(), e.percentBp(), e.region());
    }

    public static TaxRate create(AuthUser user, TaxRateDto dto) {
        return new TaxRate(Ids.next("tax"), user.tenantId(), user.id(),
                Text.required(dto.name(), "name"), dto.percentBp(), Text.plain(dto.region()));
    }

    public static TaxRate apply(TaxRate current, TaxRateDto dto) {
        return new TaxRate(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.name(), "name"), dto.percentBp(), Text.plain(dto.region()));
    }
}
