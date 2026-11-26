package com.ledger.auditentries;

import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class AuditEntryService {

    private final AuditEntryRepository repository;

    public AuditEntryService(AuditEntryRepository repository) {
        this.repository = repository;
    }

    public List<AuditEntryDto> list(AuthUser user) {
        return repository.listByTenant(user.tenantId()).stream()
                .map(AuditEntryMapper::toDto)
                .toList();
    }

    public AuditEntryDto get(AuthUser user, String id) {
        return AuditEntryMapper.toDto(scoped(user, id));
    }

    private AuditEntry scoped(AuthUser user, String id) {
        return repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("audit-entries"));
    }
}
