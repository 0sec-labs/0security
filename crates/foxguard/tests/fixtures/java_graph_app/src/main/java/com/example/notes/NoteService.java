package com.example.notes;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;

@Service
public class NoteService {
    private final JdbcTemplate jdbcTemplate;

    public NoteService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Note load(long id) {
        return jdbcTemplate.queryForObject("SELECT id, owner, body FROM notes WHERE id = " + id, new NoteMapper());
    }

    public Note save(long id, Note body) {
        jdbcTemplate.update("UPDATE notes SET body = ? WHERE id = ?", body.body(), id);
        return load(id);
    }

    public String exportRaw(long id) {
        Note n = load(id);
        try {
            return Files.readString(Path.of("/var/notes", n.body()));
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
