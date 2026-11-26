package com.ledger.locations;

import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
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
 * Reads are open to the tenant; writes are limited to managers.
 */
@RestController
@RequestMapping("/api/locations")
public class LocationController {

    private final LocationService service;

    public LocationController(LocationService service) {
        this.service = service;
    }

    @GetMapping
    public List<LocationDto> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public LocationDto get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.get(user, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    public LocationDto create(@AuthenticationPrincipal AuthUser user, @RequestBody LocationDto dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    public LocationDto update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody LocationDto dto) {
        return service.update(user, id, dto);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    public void delete(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        service.delete(user, id);
    }
}
