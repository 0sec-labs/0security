package com.ledger.assets;

import com.ledger.common.Access;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Everyone in the tenant can read these records; changes are limited to the owner or a manager.
 */
@RestController
@RequestMapping("/api/assets")
public class AssetController {

    private final AssetService service;

    public AssetController(AssetService service) {
        this.service = service;
    }

    @GetMapping
    public List<AssetDto> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public AssetDto get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.view(user, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public AssetDto create(@AuthenticationPrincipal AuthUser user, @RequestBody AssetDto dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")
    public AssetDto update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody AssetDto dto) {
        Asset current = service.find(user, id);
        Access.requireOwnerOrManager(user, current.ownerId());
        return service.update(current, dto);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        Asset current = service.find(user, id);
        Access.requireOwnerOrManager(user, current.ownerId());
        service.remove(current);
    }
}
