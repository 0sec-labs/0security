package com.ledger.departments;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class DepartmentMapper {

    private DepartmentMapper() {
    }

    public static DepartmentDto toDto(Department e) {
        return new DepartmentDto(e.id(),
                e.name(), e.code(), e.headcount());
    }

    public static Department create(AuthUser user, DepartmentDto dto) {
        return new Department(Ids.next("dep"), user.tenantId(), user.id(),
                Text.required(dto.name(), "name"), Text.plain(dto.code()), dto.headcount());
    }

    public static Department apply(Department current, DepartmentDto dto) {
        return new Department(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.name(), "name"), Text.plain(dto.code()), dto.headcount());
    }
}
