package com.ledger.policies;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class PolicyMapper {

    private PolicyMapper() {
    }

    public static PolicyDto toDto(Policy e) {
        return new PolicyDto(e.id(),
                e.name(), e.ruleKind(), e.limitCents(),
                e.active());
    }

    public static Policy create(AuthUser user, PolicyDto dto) {
        return new Policy(Ids.next("pol"), user.tenantId(), user.id(),
                Text.required(dto.name(), "name"), Text.plain(dto.ruleKind()), dto.limitCents(),
                dto.active());
    }

    public static Policy apply(Policy current, PolicyDto dto) {
        return new Policy(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.name(), "name"), Text.plain(dto.ruleKind()), dto.limitCents(),
                dto.active());
    }
}
