package com.ledger.security;

import java.util.Optional;
import org.springframework.stereotype.Service;

@Service
public class ShareTokenService {

    private static final String PREFIX = "stmt:";

    private final TokenService tokens;

    public ShareTokenService(TokenService tokens) {
        this.tokens = tokens;
    }

    public String issue(String statementId) {
        return tokens.sign(PREFIX + statementId);
    }

    /**
     * Subject of a valid share token, or empty when the token is not one of ours.
     */
    public Optional<String> subject(String token) {
        return tokens.open(token).filter(p -> p.startsWith(PREFIX)).map(p -> p.substring(PREFIX.length()));
    }
}
