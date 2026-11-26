package com.example.shop;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class OrderServiceImpl implements OrderService {
    private final JdbcTemplate jdbcTemplate;
    private final AuditLog audit;

    public OrderServiceImpl(JdbcTemplate jdbcTemplate, AuditLog audit) {
        this.jdbcTemplate = jdbcTemplate;
        this.audit = audit;
    }

    @Override
    public String load(long id) {
        audit.record("load");
        return jdbcTemplate.queryForObject("select body from orders where id = " + id, String.class);
    }

    @Override
    public String search(String q) {
        return jdbcTemplate.queryForObject("select body from orders where body like '%" + q + "%'", String.class);
    }

    @Override
    public void remove(long id) {
        audit.record("remove");
        jdbcTemplate.update("delete from orders where id = " + id);
    }
}
