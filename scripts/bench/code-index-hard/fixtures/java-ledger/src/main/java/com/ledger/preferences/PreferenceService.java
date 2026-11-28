package com.ledger.preferences;

import com.ledger.common.Access;
import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class PreferenceService {

    private final PreferenceRepository repository;

    public PreferenceService(PreferenceRepository repository) {
        this.repository = repository;
    }

    public List<PreferenceDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .filter(e -> e.ownerId().equals(user.id()))
                .map(PreferenceMapper::toDto)
                .toList();
    }

    public PreferenceDto get(AuthUser user, String id) {
        return PreferenceMapper.toDto(requireOwn(user, id));
    }

    public PreferenceDto create(AuthUser user, PreferenceDto dto) {
        return PreferenceMapper.toDto(repository.save(PreferenceMapper.create(user, dto)));
    }

    public PreferenceDto update(AuthUser user, String id, PreferenceDto dto) {
        Preference current = requireOwn(user, id);
        return PreferenceMapper.toDto(repository.save(PreferenceMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Preference current = requireOwn(user, id);
        repository.delete(current.id());
    }
    public PreferenceDto mine(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .filter(p -> p.ownerId().equals(user.id()))
                .findFirst()
                .map(PreferenceMapper::toDto)
                .orElseThrow(() -> new NotFoundException("preference"));
    }

    private Preference requireOwn(AuthUser user, String id) {
        Preference entity = repository.findById(id).orElseThrow(() -> new NotFoundException("preferences"));
        Access.requireTenant(user, entity.tenantId());
        Access.requireOwner(user, entity.ownerId());
        return entity;
    }
}
