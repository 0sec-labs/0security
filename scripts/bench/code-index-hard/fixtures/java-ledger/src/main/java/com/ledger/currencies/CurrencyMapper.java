package com.ledger.currencies;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class CurrencyMapper {

    private CurrencyMapper() {
    }

    public static CurrencyDto toDto(Currency e) {
        return new CurrencyDto(e.id(),
                e.code(), e.symbol(), e.rateMicros());
    }

    public static Currency create(AuthUser user, CurrencyDto dto) {
        return new Currency(Ids.next("cur"), user.tenantId(), user.id(),
                Text.required(dto.code(), "code"), Text.plain(dto.symbol()), dto.rateMicros());
    }

    public static Currency apply(Currency current, CurrencyDto dto) {
        return new Currency(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.code(), "code"), Text.plain(dto.symbol()), dto.rateMicros());
    }
}
