package com.ledger.categories;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;
import org.springframework.stereotype.Component;

@Component
public class CategoryMapper {

    public CategoryDto toDto(Category e) {
        return new CategoryDto(e.id(),
                e.name(), e.color(), e.archived());
    }

    public Category create(AuthUser user, CategoryDto dto) {
        return new Category(Ids.next("cat"), user.tenantId(), user.id(),
                Text.required(dto.name(), "name"), Text.plain(dto.color()), dto.archived());
    }

    public Category apply(Category current, CategoryDto dto) {
        return new Category(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.name(), "name"), Text.plain(dto.color()), dto.archived());
    }
}
