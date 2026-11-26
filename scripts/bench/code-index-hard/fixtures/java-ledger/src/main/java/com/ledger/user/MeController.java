package com.ledger.user;

import com.ledger.security.AuthUser;
import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/me")
public class MeController {

    private final UserService service;

    public MeController(UserService service) {
        this.service = service;
    }

    @GetMapping
    public ProfileDto me(@AuthenticationPrincipal AuthUser user) {
        return service.profile(user);
    }

    @PutMapping("/display-name")
    public ProfileDto rename(@AuthenticationPrincipal AuthUser user, @RequestBody Map<String, String> body) {
        return service.rename(user, body.get("displayName"));
    }
}
