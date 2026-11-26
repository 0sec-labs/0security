package com.ledger.user;

import com.ledger.common.NotFoundException;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository users;

    public UserService(UserRepository users) {
        this.users = users;
    }

    public ProfileDto profile(AuthUser actor) {
        return toDto(require(actor.id()));
    }

    public ProfileDto rename(AuthUser actor, String displayName) {
        User current = require(actor.id());
        User updated = users.save(current.withDisplayName(Text.required(displayName, "displayName")));
        return toDto(updated);
    }

    private User require(String id) {
        return users.findById(id).orElseThrow(() -> new NotFoundException("user"));
    }

    private ProfileDto toDto(User u) {
        return new ProfileDto(u.id(), u.email(), u.displayName(), u.role().name(), u.tenantId());
    }
}
