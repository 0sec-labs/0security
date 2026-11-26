package com.ledger.preferences;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class PreferenceMapper {

    private PreferenceMapper() {
    }

    public static PreferenceDto toDto(Preference e) {
        return new PreferenceDto(e.id(),
                e.locale(), e.timezone(), e.digest());
    }

    public static Preference create(AuthUser user, PreferenceDto dto) {
        return new Preference(Ids.next("prf"), user.tenantId(), user.id(),
                Text.required(dto.locale(), "locale"), Text.plain(dto.timezone()), dto.digest());
    }

    public static Preference apply(Preference current, PreferenceDto dto) {
        return new Preference(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.locale(), "locale"), Text.plain(dto.timezone()), dto.digest());
    }
}
