package com.example.notes;

import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

public class NoteMapper implements RowMapper<Note> {
    @Override
    public Note mapRow(ResultSet rs, int rowNum) throws SQLException {
        return new Note(rs.getLong("id"), rs.getString("owner"), rs.getString("body"));
    }
}
