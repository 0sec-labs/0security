package com.ledger.savedfilters;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class SavedFilterMapper {

    private SavedFilterMapper() {
    }

    public static SavedFilterDto toDto(SavedFilter e) {
        return new SavedFilterDto(e.id(),
                e.name(), e.query());
    }

    public static SavedFilter create(AuthUser user, SavedFilterDto dto) {
        return new SavedFilter(Ids.next("flt"), user.tenantId(), user.id(),
                Text.required(dto.name(), "name"), Text.plain(dto.query()));
    }

    public static SavedFilter apply(SavedFilter current, SavedFilterDto dto) {
        return new SavedFilter(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.name(), "name"), Text.plain(dto.query()));
    }
}
