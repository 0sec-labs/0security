package com.ledger.web;

import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The published price list shown on the marketing site.
 */
@RestController
@RequestMapping("/public/plans")
public class PublicPlanController {

    public record PlanListing(String code, String name, int monthlyPriceCents, int includedSeats) {
    }

    @GetMapping
    public List<PlanListing> plans() {
        return List.of(
                new PlanListing("starter", "Starter", 4900, 5),
                new PlanListing("team", "Team", 19900, 25),
                new PlanListing("business", "Business", 74900, 100));
    }
}
