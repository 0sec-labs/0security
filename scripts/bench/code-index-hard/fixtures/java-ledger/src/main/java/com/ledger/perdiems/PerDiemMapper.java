package com.ledger.perdiems;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;
import org.springframework.stereotype.Component;

@Component
public class PerDiemMapper {

    public PerDiemDto toDto(PerDiem e) {
        return new PerDiemDto(e.id(),
                e.destination(), e.days(), e.rateCents());
    }

    public PerDiem create(AuthUser user, PerDiemDto dto) {
        return new PerDiem(Ids.next("pdm"), user.tenantId(), user.id(),
                Text.required(dto.destination(), "destination"), dto.days(), dto.rateCents());
    }

    public PerDiem apply(PerDiem current, PerDiemDto dto) {
        return new PerDiem(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.destination(), "destination"), dto.days(), dto.rateCents());
    }
}
