package com.ledger.admin;

import com.ledger.security.AuthUser;
import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/stats")
public class AdminStatsController {

    private final AdminService service;

    public AdminStatsController(AdminService service) {
        this.service = service;
    }

    @GetMapping
    public Map<String, Integer> stats(@AuthenticationPrincipal AuthUser user) {
        return service.stats(user);
    }
}
