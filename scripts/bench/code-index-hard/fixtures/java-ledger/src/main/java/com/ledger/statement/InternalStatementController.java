package com.ledger.statement;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Used by the month-end batch. The /internal routes are limited to the service role in the security configuration.
 */
@RestController
@RequestMapping("/internal/statements")
public class InternalStatementController {

    private final StatementService service;

    public InternalStatementController(StatementService service) {
        this.service = service;
    }

    @GetMapping("/{id}")
    public StatementView get(@PathVariable String id) {
        return service.build(id);
    }
}
