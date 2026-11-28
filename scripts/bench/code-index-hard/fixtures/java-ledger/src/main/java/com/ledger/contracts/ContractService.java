package com.ledger.contracts;

import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.time.LocalDate;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class ContractService {

    private final ContractRepository repository;

    public ContractService(ContractRepository repository) {
        this.repository = repository;
    }

    public List<ContractDto> list(AuthUser user) {
        return repository.listByTenant(user.tenantId()).stream()
                .map(ContractMapper::toDto)
                .toList();
    }

    public ContractDto get(AuthUser user, String id) {
        return ContractMapper.toDto(scoped(user, id));
    }

    public ContractDto create(AuthUser user, ContractDto dto) {
        return ContractMapper.toDto(repository.save(ContractMapper.create(user, dto)));
    }

    public ContractDto update(AuthUser user, String id, ContractDto dto) {
        Contract current = scoped(user, id);
        return ContractMapper.toDto(repository.save(ContractMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Contract current = scoped(user, id);
        repository.removeInTenant(user.tenantId(), current.id());
    }
    public List<ContractDto> expiring(AuthUser user, int days) {
        LocalDate limit = LocalDate.now().plusDays(days);
        return list(user).stream().filter(c -> c.endsOn() != null && !c.endsOn().isAfter(limit)).toList();
    }

    private Contract scoped(AuthUser user, String id) {
        return repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("contracts"));
    }
}
