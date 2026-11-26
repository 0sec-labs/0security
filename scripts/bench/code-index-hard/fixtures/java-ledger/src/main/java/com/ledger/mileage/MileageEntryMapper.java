package com.ledger.mileage;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;
import org.springframework.stereotype.Component;

@Component
public class MileageEntryMapper {

    public MileageEntryDto toDto(MileageEntry e) {
        return new MileageEntryDto(e.id(),
                e.purpose(), e.tripDate(), e.distanceKm());
    }

    public MileageEntry create(AuthUser user, MileageEntryDto dto) {
        return new MileageEntry(Ids.next("mil"), user.tenantId(), user.id(),
                Text.required(dto.purpose(), "purpose"), dto.tripDate(), dto.distanceKm());
    }

    public MileageEntry apply(MileageEntry current, MileageEntryDto dto) {
        return new MileageEntry(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.purpose(), "purpose"), dto.tripDate(), dto.distanceKm());
    }
}
