package com.ledger.policies;

import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class PolicyService {

    private final PolicyRepository repository;

    public PolicyService(PolicyRepository repository) {
        this.repository = repository;
    }

    public List<PolicyDto> list(AuthUser user) {
        return repository.listByTenant(user.tenantId()).stream()
                .map(PolicyMapper::toDto)
                .toList();
    }

    public PolicyDto get(AuthUser user, String id) {
        return PolicyMapper.toDto(scoped(user, id));
    }

    public PolicyDto create(AuthUser user, PolicyDto dto) {
        return PolicyMapper.toDto(repository.save(PolicyMapper.create(user, dto)));
    }

    public PolicyDto update(AuthUser user, String id, PolicyDto dto) {
        Policy current = scoped(user, id);
        return PolicyMapper.toDto(repository.save(PolicyMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Policy current = scoped(user, id);
        repository.removeInTenant(user.tenantId(), current.id());
    }

    private Policy scoped(AuthUser user, String id) {
        return repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("policies"));
    }
}
