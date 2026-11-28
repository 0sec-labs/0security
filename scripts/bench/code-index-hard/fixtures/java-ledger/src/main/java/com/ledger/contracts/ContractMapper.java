package com.ledger.contracts;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class ContractMapper {

    private ContractMapper() {
    }

    public static ContractDto toDto(Contract e) {
        return new ContractDto(e.id(),
                e.title(), e.counterparty(), e.startsOn(),
                e.endsOn(), e.valueCents());
    }

    public static Contract create(AuthUser user, ContractDto dto) {
        return new Contract(Ids.next("con"), user.tenantId(), user.id(),
                Text.required(dto.title(), "title"), Text.plain(dto.counterparty()), dto.startsOn(),
                dto.endsOn(), dto.valueCents());
    }

    public static Contract apply(Contract current, ContractDto dto) {
        return new Contract(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.title(), "title"), Text.plain(dto.counterparty()), dto.startsOn(),
                dto.endsOn(), dto.valueCents());
    }
}
