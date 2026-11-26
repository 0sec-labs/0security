package com.ledger.auditentries;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class AuditEntryMapper {

    private AuditEntryMapper() {
    }

    public static AuditEntryDto toDto(AuditEntry e) {
        return new AuditEntryDto(e.id(),
                e.action(), e.subject(), e.detail());
    }

    public static AuditEntry create(AuthUser user, AuditEntryDto dto) {
        return new AuditEntry(Ids.next("aud"), user.tenantId(), user.id(),
                Text.required(dto.action(), "action"), Text.plain(dto.subject()), Text.plain(dto.detail()));
    }

    public static AuditEntry apply(AuditEntry current, AuditEntryDto dto) {
        return new AuditEntry(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.action(), "action"), Text.plain(dto.subject()), Text.plain(dto.detail()));
    }
}
