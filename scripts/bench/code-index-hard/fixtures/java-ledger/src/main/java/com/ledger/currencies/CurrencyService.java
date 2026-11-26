package com.ledger.currencies;

import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class CurrencyService {

    private final CurrencyRepository repository;

    public CurrencyService(CurrencyRepository repository) {
        this.repository = repository;
    }

    public List<CurrencyDto> list(AuthUser user) {
        return repository.listByTenant(user.tenantId()).stream()
                .map(CurrencyMapper::toDto)
                .toList();
    }

    public CurrencyDto get(AuthUser user, String id) {
        return CurrencyMapper.toDto(scoped(user, id));
    }

    public CurrencyDto create(AuthUser user, CurrencyDto dto) {
        return CurrencyMapper.toDto(repository.save(CurrencyMapper.create(user, dto)));
    }

    public CurrencyDto update(AuthUser user, String id, CurrencyDto dto) {
        Currency current = scoped(user, id);
        return CurrencyMapper.toDto(repository.save(CurrencyMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Currency current = scoped(user, id);
        repository.removeInTenant(user.tenantId(), current.id());
    }
    public long convert(AuthUser user, String from, String to, long amountCents) {
        Currency source = byCode(user, from);
        Currency target = byCode(user, to);
        return amountCents * source.rateMicros() / target.rateMicros();
    }

    private Currency byCode(AuthUser user, String code) {
        return repository.listByTenant(user.tenantId()).stream()
                .filter(c -> c.code().equalsIgnoreCase(code))
                .findFirst()
                .orElseThrow(() -> new NotFoundException("currency"));
    }

    private Currency scoped(AuthUser user, String id) {
        return repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("currencies"));
    }
}
