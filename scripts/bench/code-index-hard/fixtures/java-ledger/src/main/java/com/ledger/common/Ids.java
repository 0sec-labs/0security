package com.ledger.common;

import java.util.concurrent.atomic.AtomicLong;

public final class Ids {

    private static final AtomicLong SEQUENCE = new AtomicLong(1000);

    private Ids() {
    }

    public static String next(String prefix) {
        return prefix + "-" + SEQUENCE.incrementAndGet();
    }
}
