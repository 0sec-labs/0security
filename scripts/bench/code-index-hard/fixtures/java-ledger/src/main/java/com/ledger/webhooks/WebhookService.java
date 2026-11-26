package com.ledger.webhooks;

import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class WebhookService {

    private final WebhookRepository repository;

    public WebhookService(WebhookRepository repository) {
        this.repository = repository;
    }

    public List<WebhookDto> list(AuthUser user) {
        return repository.listByTenant(user.tenantId()).stream()
                .map(WebhookMapper::toDto)
                .toList();
    }

    public WebhookDto get(AuthUser user, String id) {
        return WebhookMapper.toDto(scoped(user, id));
    }

    public WebhookDto create(AuthUser user, WebhookDto dto) {
        return WebhookMapper.toDto(repository.save(WebhookMapper.create(user, dto)));
    }

    public WebhookDto update(AuthUser user, String id, WebhookDto dto) {
        Webhook current = scoped(user, id);
        return WebhookMapper.toDto(repository.save(WebhookMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Webhook current = scoped(user, id);
        repository.removeInTenant(user.tenantId(), current.id());
    }
    public Map<String, Object> ping(AuthUser user, String id) {
        Webhook hook = scoped(user, id);
        return Map.of("event", hook.event(), "active", hook.active());
    }

    private Webhook scoped(AuthUser user, String id) {
        return repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("webhooks"));
    }
}
