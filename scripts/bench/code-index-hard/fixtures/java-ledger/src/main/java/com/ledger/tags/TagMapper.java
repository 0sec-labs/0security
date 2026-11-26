package com.ledger.tags;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;
import org.springframework.stereotype.Component;

@Component
public class TagMapper {

    public TagDto toDto(Tag e) {
        return new TagDto(e.id(),
                e.label(), e.color());
    }

    public Tag create(AuthUser user, TagDto dto) {
        return new Tag(Ids.next("tag"), user.tenantId(), user.id(),
                Text.required(dto.label(), "label"), Text.plain(dto.color()));
    }

    public Tag apply(Tag current, TagDto dto) {
        return new Tag(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.label(), "label"), Text.plain(dto.color()));
    }
}
