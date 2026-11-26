package com.ledger.notes;

public record NoteDto(String id,
        String body, String linkedExpenseId) {
}
