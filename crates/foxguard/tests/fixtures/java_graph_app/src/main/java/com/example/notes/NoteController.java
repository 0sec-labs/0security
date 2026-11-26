package com.example.notes;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/notes")
public class NoteController {
    private final NoteService notes;
    private final OwnershipChecker ownership;

    public NoteController(NoteService notes, OwnershipChecker ownership) {
        this.notes = notes;
        this.ownership = ownership;
    }

    // Guarded by an annotation.
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/{id}")
    public ResponseEntity<Note> get(@PathVariable long id) {
        return ResponseEntity.ok(notes.load(id));
    }

    // Guarded by an ownership check in the handler body.
    @PutMapping("/{id}")
    public ResponseEntity<Note> update(@PathVariable long id, @RequestBody Note body, Principal user) {
        Note existing = notes.load(id);
        ownership.assertOwner(user.getName(), existing);
        return ResponseEntity.ok(notes.save(id, body));
    }

    // No authentication, authorization or ownership check anywhere on this path.
    @GetMapping("/{id}/export")
    public String export(@PathVariable long id) {
        return notes.exportRaw(id);
    }
}
