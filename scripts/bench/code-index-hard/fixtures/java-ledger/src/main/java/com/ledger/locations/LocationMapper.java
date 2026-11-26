package com.ledger.locations;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class LocationMapper {

    private LocationMapper() {
    }

    public static LocationDto toDto(Location e) {
        return new LocationDto(e.id(),
                e.name(), e.city(), e.country());
    }

    public static Location create(AuthUser user, LocationDto dto) {
        return new Location(Ids.next("loc"), user.tenantId(), user.id(),
                Text.required(dto.name(), "name"), Text.plain(dto.city()), Text.plain(dto.country()));
    }

    public static Location apply(Location current, LocationDto dto) {
        return new Location(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.name(), "name"), Text.plain(dto.city()), Text.plain(dto.country()));
    }
}
