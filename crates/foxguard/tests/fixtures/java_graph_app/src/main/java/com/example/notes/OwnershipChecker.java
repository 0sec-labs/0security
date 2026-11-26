package com.example.notes;

import org.springframework.stereotype.Component;

@Component
public class OwnershipChecker {
    public void assertOwner(String user, Note note) {
        if (!note.owner().equals(user)) {
            throw new SecurityException("not the owner");
        }
    }
}
