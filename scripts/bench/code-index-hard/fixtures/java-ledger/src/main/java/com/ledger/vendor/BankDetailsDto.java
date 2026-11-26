package com.ledger.vendor;

public record BankDetailsDto(String accountName, String iban, String bic) {

    public static BankDetailsDto masked(BankDetails details) {
        if (details == null) {
            return new BankDetailsDto(null, null, null);
        }
        String iban = details.iban();
        String tail = iban == null || iban.length() < 4 ? "" : iban.substring(iban.length() - 4);
        return new BankDetailsDto(details.accountName(), "****" + tail, details.bic());
    }
}
