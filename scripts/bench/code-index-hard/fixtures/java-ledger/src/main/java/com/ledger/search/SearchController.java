package com.ledger.search;

import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/search")
public class SearchController {

    private final GlobalSearchService service;

    public SearchController(GlobalSearchService service) {
        this.service = service;
    }

    @GetMapping
    public List<SearchHit> search(@AuthenticationPrincipal AuthUser user, @RequestParam("q") String query) {
        return service.search(user, query);
    }
}
