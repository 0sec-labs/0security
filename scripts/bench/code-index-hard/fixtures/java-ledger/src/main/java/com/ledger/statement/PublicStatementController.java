package com.ledger.statement;

import com.ledger.common.ForbiddenException;
import com.ledger.security.ShareTokenService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/public/statements")
public class PublicStatementController {

    private final StatementService service;
    private final ShareTokenService shareTokens;

    public PublicStatementController(StatementService service, ShareTokenService shareTokens) {
        this.service = service;
        this.shareTokens = shareTokens;
    }

    @GetMapping("/{id}")
    public StatementView shared(@PathVariable String id, @RequestParam("token") String token) {
        shareTokens.subject(token).orElseThrow(() -> new ForbiddenException("invalid share link"));
        return service.build(id);
    }
}
