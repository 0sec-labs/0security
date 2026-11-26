package com.example.shop;

import org.springframework.stereotype.Component;

@Component
public class AuditLog {
    public void record(String what) {
        System.out.println(what);
    }
}
