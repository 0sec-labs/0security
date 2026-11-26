package com.ledger.perdiems;

import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class PerDiemService {

    private final PerDiemRepository repository;
    private final PerDiemMapper mapper;

    public PerDiemService(PerDiemRepository repository, PerDiemMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    public List<PerDiemDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .map(mapper::toDto)
                .toList();
    }

    public PerDiem find(AuthUser user, String id) {
        return repository.findById(id)
                .filter(e -> e.tenantId().equals(user.tenantId()))
                .orElseThrow(() -> new NotFoundException("per-diems"));
    }

    public PerDiemDto view(AuthUser user, String id) {
        return mapper.toDto(find(user, id));
    }

    public PerDiemDto create(AuthUser user, PerDiemDto dto) {
        return mapper.toDto(repository.save(mapper.create(user, dto)));
    }

    public PerDiemDto update(PerDiem current, PerDiemDto dto) {
        return mapper.toDto(repository.save(mapper.apply(current, dto)));
    }

    public void remove(PerDiem current) {
        repository.delete(current.id());
    }
}
