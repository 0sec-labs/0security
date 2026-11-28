package com.ledger.security;

import com.ledger.config.LedgerProperties;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    private static final String ALGORITHM = "HmacSHA256";

    private final byte[] key;

    public TokenService(LedgerProperties properties) {
        String configured = properties.tokenSecret();
        if (configured == null || configured.isBlank()) {
            byte[] random = new byte[32];
            new SecureRandom().nextBytes(random);
            this.key = random;
        } else {
            this.key = configured.getBytes(StandardCharsets.UTF_8);
        }
    }

    public String issue(String userId) {
        return sign(userId);
    }

    /**
     * Returns the signed payload as "payload.signature".
     */
    public String sign(String payload) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "." + encoder.encodeToString(mac(payload));
    }

    /**
     * Verifies the signature and returns the payload, or empty when the token is malformed or forged.
     */
    public Optional<String> open(String token) {
        if (token == null) {
            return Optional.empty();
        }
        int dot = token.indexOf('.');
        if (dot <= 0 || dot == token.length() - 1) {
            return Optional.empty();
        }
        try {
            byte[] payloadBytes = Base64.getUrlDecoder().decode(token.substring(0, dot));
            byte[] signature = Base64.getUrlDecoder().decode(token.substring(dot + 1));
            String payload = new String(payloadBytes, StandardCharsets.UTF_8);
            if (MessageDigest.isEqual(mac(payload), signature)) {
                return Optional.of(payload);
            }
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    private byte[] mac(String payload) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(key, ALGORITHM));
            return mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        } catch (java.security.GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
