package com.example.shop;

public interface OrderService {
    String load(long id);

    String search(String q);

    void remove(long id);
}
