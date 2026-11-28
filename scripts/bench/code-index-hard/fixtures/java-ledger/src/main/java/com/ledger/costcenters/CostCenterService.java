package com.ledger.costcenters;

import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class CostCenterService {

    private final CostCenterRepository repository;

    public CostCenterService(CostCenterRepository repository) {
        this.repository = repository;
    }

    public List<CostCenterDto> list(AuthUser user) {
        return repository.listByTenant(user.tenantId()).stream()
                .map(CostCenterMapper::toDto)
                .toList();
    }

    public CostCenterDto get(AuthUser user, String id) {
        return CostCenterMapper.toDto(scoped(user, id));
    }

    public CostCenterDto create(AuthUser user, CostCenterDto dto) {
        return CostCenterMapper.toDto(repository.save(CostCenterMapper.create(user, dto)));
    }

    public CostCenterDto update(AuthUser user, String id, CostCenterDto dto) {
        CostCenter current = scoped(user, id);
        return CostCenterMapper.toDto(repository.save(CostCenterMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        CostCenter current = scoped(user, id);
        repository.removeInTenant(user.tenantId(), current.id());
    }

    private CostCenter scoped(AuthUser user, String id) {
        return repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("cost-centers"));
    }
}
