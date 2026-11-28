package com.ledger.vendor;

import com.ledger.common.Ids;
import com.ledger.common.NotFoundException;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class VendorService {

    private final VendorRepository repository;
    private final VendorMapper mapper;

    public VendorService(VendorRepository repository, VendorMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    public List<VendorDto> list(String tenantId) {
        return repository.listByTenant(tenantId).stream().map(mapper::toDto).toList();
    }

    public VendorDto get(String tenantId, String id) {
        return mapper.toDto(require(tenantId, id));
    }

    public VendorDto create(String tenantId, VendorDto dto) {
        return mapper.toDto(repository.save(mapper.create(tenantId, dto)));
    }

    public VendorDto update(String tenantId, String id, VendorDto dto) {
        return mapper.toDto(repository.save(mapper.apply(require(tenantId, id), dto)));
    }

    public VendorDto setStatus(String tenantId, String id, String status) {
        return mapper.toDto(repository.save(require(tenantId, id).withStatus(status)));
    }

    public List<VendorContact> contacts(String tenantId, String id) {
        return repository.contactsOf(require(tenantId, id).id());
    }

    public VendorContact addContact(String tenantId, String id, VendorContact input) {
        Vendor vendor = require(tenantId, id);
        return repository.saveContact(new VendorContact(Ids.next("vc"), vendor.id(), input.name(), input.email()));
    }

    public BankDetailsDto bankDetails(String tenantId, String id) {
        return BankDetailsDto.masked(require(tenantId, id).bank());
    }

    public BankDetailsDto replaceBankDetails(String tenantId, String id, BankDetailsDto details, String changedBy) {
        Vendor vendor = require(tenantId, id);
        BankDetails next = new BankDetails(details.accountName(), details.iban(), details.bic(), changedBy);
        return BankDetailsDto.masked(repository.save(vendor.withBank(next)).bank());
    }

    private Vendor require(String tenantId, String id) {
        return repository.findInTenant(tenantId, id).orElseThrow(() -> new NotFoundException("vendor"));
    }
}
