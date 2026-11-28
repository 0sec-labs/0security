package com.ledger.mileage;

import com.ledger.security.AuthUser;
import java.util.List;
import java.util.Map;
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

@RestController
@RequestMapping("/api/mileage")
public class MileageEntryController {

    private final MileageEntryService service;

    public MileageEntryController(MileageEntryService service) {
        this.service = service;
    }

    @GetMapping
    public List<MileageEntryDto> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public MileageEntryDto get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.get(user, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public MileageEntryDto create(@AuthenticationPrincipal AuthUser user, @RequestBody MileageEntryDto dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")
    public MileageEntryDto update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody MileageEntryDto dto) {
        return service.update(user, id, dto);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        service.delete(user, id);
    }

    @GetMapping("/summary")
    public Map<String, Integer> summary(@AuthenticationPrincipal AuthUser user) {
        return service.summary(user);
    }
}
