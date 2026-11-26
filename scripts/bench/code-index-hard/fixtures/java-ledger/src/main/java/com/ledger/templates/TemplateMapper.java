package com.ledger.templates;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class TemplateMapper {

    private TemplateMapper() {
    }

    public static TemplateDto toDto(Template e) {
        return new TemplateDto(e.id(),
                e.name(), e.kind(), e.body());
    }

    public static Template create(AuthUser user, TemplateDto dto) {
        return new Template(Ids.next("tpl"), user.tenantId(), user.id(),
                Text.required(dto.name(), "name"), Text.plain(dto.kind()), Text.plain(dto.body()));
    }

    public static Template apply(Template current, TemplateDto dto) {
        return new Template(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.name(), "name"), Text.plain(dto.kind()), Text.plain(dto.body()));
    }
}
