package com.ledger.assets;

import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class AssetService {

    private final AssetRepository repository;
    private final AssetMapper mapper;

    public AssetService(AssetRepository repository, AssetMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    public List<AssetDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .map(mapper::toDto)
                .toList();
    }

    public Asset find(AuthUser user, String id) {
        return repository.findById(id)
                .filter(e -> e.tenantId().equals(user.tenantId()))
                .orElseThrow(() -> new NotFoundException("assets"));
    }

    public AssetDto view(AuthUser user, String id) {
        return mapper.toDto(find(user, id));
    }

    public AssetDto create(AuthUser user, AssetDto dto) {
        return mapper.toDto(repository.save(mapper.create(user, dto)));
    }

    public AssetDto update(Asset current, AssetDto dto) {
        return mapper.toDto(repository.save(mapper.apply(current, dto)));
    }

    public void remove(Asset current) {
        repository.delete(current.id());
    }
}
