package com.ledger.reports;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;
import org.springframework.stereotype.Component;

@Component
public class ReportMapper {

    public ReportDto toDto(Report e) {
        return new ReportDto(e.id(),
                e.title(), e.kind(), e.parameters());
    }

    public Report create(AuthUser user, ReportDto dto) {
        return new Report(Ids.next("rpt"), user.tenantId(), user.id(),
                Text.required(dto.title(), "title"), Text.plain(dto.kind()), Text.plain(dto.parameters()));
    }

    public Report apply(Report current, ReportDto dto) {
        return new Report(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.title(), "title"), Text.plain(dto.kind()), Text.plain(dto.parameters()));
    }
}
