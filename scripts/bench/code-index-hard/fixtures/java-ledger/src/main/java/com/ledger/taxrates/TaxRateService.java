package com.ledger.taxrates;

import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class TaxRateService {

    private final TaxRateRepository repository;

    public TaxRateService(TaxRateRepository repository) {
        this.repository = repository;
    }

    public List<TaxRateDto> list(AuthUser user) {
        return repository.listByTenant(user.tenantId()).stream()
                .map(TaxRateMapper::toDto)
                .toList();
    }

    public TaxRateDto get(AuthUser user, String id) {
        return TaxRateMapper.toDto(scoped(user, id));
    }

    public TaxRateDto create(AuthUser user, TaxRateDto dto) {
        return TaxRateMapper.toDto(repository.save(TaxRateMapper.create(user, dto)));
    }

    public TaxRateDto update(AuthUser user, String id, TaxRateDto dto) {
        TaxRate current = scoped(user, id);
        return TaxRateMapper.toDto(repository.save(TaxRateMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        TaxRate current = scoped(user, id);
        repository.removeInTenant(user.tenantId(), current.id());
    }
    public long apply(AuthUser user, String id, long amountCents) {
        TaxRate rate = scoped(user, id);
        return amountCents * rate.percentBp() / 10000;
    }

    private TaxRate scoped(AuthUser user, String id) {
        return repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("tax-rates"));
    }
}
