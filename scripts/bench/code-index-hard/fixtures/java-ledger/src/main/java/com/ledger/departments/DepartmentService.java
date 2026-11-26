package com.ledger.departments;

import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class DepartmentService {

    private final DepartmentRepository repository;

    public DepartmentService(DepartmentRepository repository) {
        this.repository = repository;
    }

    public List<DepartmentDto> list(AuthUser user) {
        return repository.listByTenant(user.tenantId()).stream()
                .map(DepartmentMapper::toDto)
                .toList();
    }

    public DepartmentDto get(AuthUser user, String id) {
        return DepartmentMapper.toDto(scoped(user, id));
    }

    public DepartmentDto create(AuthUser user, DepartmentDto dto) {
        return DepartmentMapper.toDto(repository.save(DepartmentMapper.create(user, dto)));
    }

    public DepartmentDto update(AuthUser user, String id, DepartmentDto dto) {
        Department current = scoped(user, id);
        return DepartmentMapper.toDto(repository.save(DepartmentMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Department current = scoped(user, id);
        repository.removeInTenant(user.tenantId(), current.id());
    }

    private Department scoped(AuthUser user, String id) {
        return repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("departments"));
    }
}
