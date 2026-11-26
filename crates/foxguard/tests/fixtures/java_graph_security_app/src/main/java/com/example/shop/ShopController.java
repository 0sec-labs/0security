package com.example.shop;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Files;
import java.nio.file.Path;

@RestController
public class ShopController {
    @Autowired
    private OrderService orders;

    // Open on purpose (permitAll in SecurityConfig) and it reaches SQL: public, and still unguarded.
    @GetMapping("/public/search")
    public String search(@RequestParam String q) {
        return orders.search(q);
    }

    // Covered by `anyRequest().authenticated()`; no annotation on the method.
    @GetMapping("/shop/orders/{id}")
    public String order(@PathVariable long id) {
        return orders.load(id);
    }

    // Covered by the DELETE-specific hasRole rule.
    @DeleteMapping("/shop/orders/{id}")
    public void remove(@PathVariable long id) {
        orders.remove(id);
    }

    // Covered by hasAuthority("ADMIN") and reaches a file sink.
    @GetMapping("/admin/export")
    public String export(@RequestParam String name) throws Exception {
        return Files.readString(Path.of("/exports", name));
    }
}
