package com.ledger.common;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ErrorHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorBody> handle(ApiException ex) {
        return ResponseEntity.status(ex.status()).body(new ErrorBody(ex.getMessage()));
    }
}
