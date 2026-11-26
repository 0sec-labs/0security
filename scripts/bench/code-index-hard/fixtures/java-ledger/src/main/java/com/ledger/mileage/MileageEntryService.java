package com.ledger.mileage;

import com.ledger.common.Access;
import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class MileageEntryService {

    private final MileageEntryRepository repository;
    private final MileageEntryMapper mapper;

    public MileageEntryService(MileageEntryRepository repository, MileageEntryMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    public List<MileageEntryDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .map(mapper::toDto)
                .toList();
    }

    public MileageEntryDto get(AuthUser user, String id) {
        return mapper.toDto(require(user, id));
    }

    public MileageEntryDto create(AuthUser user, MileageEntryDto dto) {
        return mapper.toDto(repository.save(mapper.create(user, dto)));
    }

    public MileageEntryDto update(AuthUser user, String id, MileageEntryDto dto) {
        MileageEntry current = require(user, id);
        return mapper.toDto(repository.save(mapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        MileageEntry current = require(user, id);
        repository.delete(current.id());
    }
    public Map<String, Integer> summary(AuthUser user) {
        int total = repository.findByTenant(user.tenantId()).stream()
                .filter(e -> e.ownerId().equals(user.id()))
                .mapToInt(MileageEntry::distanceKm)
                .sum();
        return Map.of("totalKm", total);
    }

    private MileageEntry require(AuthUser user, String id) {
        MileageEntry entity = repository.findById(id).orElseThrow(() -> new NotFoundException("mileage"));
        Access.requireTenant(user, entity.tenantId());
        Access.requireOwnerOrManager(user, entity.ownerId());
        return entity;
    }
}
