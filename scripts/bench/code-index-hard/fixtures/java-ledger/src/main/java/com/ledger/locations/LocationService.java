package com.ledger.locations;

import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class LocationService {

    private final LocationRepository repository;

    public LocationService(LocationRepository repository) {
        this.repository = repository;
    }

    public List<LocationDto> list(AuthUser user) {
        return repository.listByTenant(user.tenantId()).stream()
                .map(LocationMapper::toDto)
                .toList();
    }

    public LocationDto get(AuthUser user, String id) {
        return LocationMapper.toDto(scoped(user, id));
    }

    public LocationDto create(AuthUser user, LocationDto dto) {
        return LocationMapper.toDto(repository.save(LocationMapper.create(user, dto)));
    }

    public LocationDto update(AuthUser user, String id, LocationDto dto) {
        Location current = scoped(user, id);
        return LocationMapper.toDto(repository.save(LocationMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Location current = scoped(user, id);
        repository.removeInTenant(user.tenantId(), current.id());
    }

    private Location scoped(AuthUser user, String id) {
        return repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("locations"));
    }
}
