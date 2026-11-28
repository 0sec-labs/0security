package com.ledger.apikeys;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class ApiKeyMapper {

    private ApiKeyMapper() {
    }

    public static ApiKeyDto toDto(ApiKey e) {
        return new ApiKeyDto(e.id(),
                e.label(), e.prefix(), e.scope());
    }

    public static ApiKey create(AuthUser user, ApiKeyDto dto) {
        return new ApiKey(Ids.next("key"), user.tenantId(), user.id(),
                Text.required(dto.label(), "label"), Text.plain(dto.prefix()), Text.plain(dto.scope()));
    }

    public static ApiKey apply(ApiKey current, ApiKeyDto dto) {
        return new ApiKey(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.label(), "label"), Text.plain(dto.prefix()), Text.plain(dto.scope()));
    }
}
