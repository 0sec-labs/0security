package com.ledger.apikeys;

import com.ledger.common.Access;
import com.ledger.common.Ids;
import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class ApiKeyService {

    private final ApiKeyRepository repository;

    public ApiKeyService(ApiKeyRepository repository) {
        this.repository = repository;
    }

    public List<ApiKeyDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .filter(e -> e.ownerId().equals(user.id()))
                .map(ApiKeyMapper::toDto)
                .toList();
    }

    public ApiKeyDto get(AuthUser user, String id) {
        return ApiKeyMapper.toDto(requireOwn(user, id));
    }

    public ApiKeyDto create(AuthUser user, ApiKeyDto dto) {
        return ApiKeyMapper.toDto(repository.save(ApiKeyMapper.create(user, dto)));
    }

    public ApiKeyDto update(AuthUser user, String id, ApiKeyDto dto) {
        ApiKey current = requireOwn(user, id);
        return ApiKeyMapper.toDto(repository.save(ApiKeyMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        ApiKey current = requireOwn(user, id);
        repository.delete(current.id());
    }
    public ApiKeyDto rotate(AuthUser user, String id) {
        ApiKey current = requireOwn(user, id);
        String fresh = "lk_" + Ids.next("k").substring(2);
        ApiKey next = new ApiKey(current.id(), current.tenantId(), current.ownerId(), current.label(), fresh, current.scope());
        return ApiKeyMapper.toDto(repository.save(next));
    }

    private ApiKey requireOwn(AuthUser user, String id) {
        ApiKey entity = repository.findById(id).orElseThrow(() -> new NotFoundException("api-keys"));
        Access.requireTenant(user, entity.tenantId());
        Access.requireOwner(user, entity.ownerId());
        return entity;
    }
}
