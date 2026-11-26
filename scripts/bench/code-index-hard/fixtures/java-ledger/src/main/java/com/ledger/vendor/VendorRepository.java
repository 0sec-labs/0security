package com.ledger.vendor;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class VendorRepository {

    private final Map<String, Vendor> store = new ConcurrentHashMap<>();
    private final Map<String, VendorContact> contacts = new ConcurrentHashMap<>();

    public Vendor save(Vendor vendor) {
        store.put(vendor.id(), vendor);
        return vendor;
    }

    public Optional<Vendor> findInTenant(String tenantId, String id) {
        return Optional.ofNullable(store.get(id)).filter(v -> v.tenantId().equals(tenantId));
    }

    public List<Vendor> listByTenant(String tenantId) {
        return store.values().stream()
                .filter(v -> v.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Vendor::id))
                .toList();
    }

    public List<Vendor> search(String tenantId, String query) {
        String needle = query.toLowerCase();
        return listByTenant(tenantId).stream().filter(v -> v.name().toLowerCase().contains(needle)).toList();
    }

    public VendorContact saveContact(VendorContact contact) {
        contacts.put(contact.id(), contact);
        return contact;
    }

    public List<VendorContact> contactsOf(String vendorId) {
        return new ArrayList<>(contacts.values().stream()
                .filter(c -> c.vendorId().equals(vendorId))
                .sorted(Comparator.comparing(VendorContact::id))
                .toList());
    }
}
