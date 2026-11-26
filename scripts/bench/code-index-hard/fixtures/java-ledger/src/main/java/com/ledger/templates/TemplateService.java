package com.ledger.templates;

import com.ledger.common.NotFoundException;
import com.ledger.common.Text;
import com.ledger.config.LedgerProperties;
import com.ledger.security.AuthUser;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class TemplateService {

    private final TemplateRepository repository;
    private final LedgerProperties properties;

    public TemplateService(TemplateRepository repository, LedgerProperties properties) {
        this.repository = repository;
        this.properties = properties;
    }

    public List<TemplateDto> list(AuthUser user) {
        return repository.listByTenant(user.tenantId()).stream()
                .map(TemplateMapper::toDto)
                .toList();
    }

    public TemplateDto get(AuthUser user, String id) {
        return TemplateMapper.toDto(scoped(user, id));
    }

    public TemplateDto create(AuthUser user, TemplateDto dto) {
        return TemplateMapper.toDto(repository.save(TemplateMapper.create(user, dto)));
    }

    public TemplateDto update(AuthUser user, String id, TemplateDto dto) {
        Template current = scoped(user, id);
        return TemplateMapper.toDto(repository.save(TemplateMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Template current = scoped(user, id);
        repository.removeInTenant(user.tenantId(), current.id());
    }
    public String publish(AuthUser user, String id) {
        Template current = scoped(user, id);
        Path dir = properties.templatePath().resolve(user.tenantId());
        Path target = dir.resolve(Text.safeSegment(current.name()) + ".tpl");
        try {
            Files.createDirectories(dir);
            Files.writeString(target, current.body() == null ? "" : current.body());
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return target.getFileName().toString();
    }

    private Template scoped(AuthUser user, String id) {
        return repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("templates"));
    }
}
