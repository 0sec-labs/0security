package com.ledger.common;

public class NotFoundException extends ApiException {

    public NotFoundException(String what) {
        super(404, what + " not found");
    }
}
