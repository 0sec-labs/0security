package com.ledger.admin;

import com.ledger.security.AuthUser;
import com.ledger.user.User;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {

    private final AdminService service;

    public AdminUserController(AdminService service) {
        this.service = service;
    }

    @GetMapping
    public List<User> list(@AuthenticationPrincipal AuthUser user) {
        return service.listUsers(user);
    }

    @PutMapping("/{id}/roles")
    public User changeRole(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody RoleChange change) {
        return service.changeRole(user, id, change.role());
    }

    @PostMapping("/{id}/deactivate")
    public User deactivate(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.deactivate(user, id);
    }
}
