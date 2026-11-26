package com.ledger.notes;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;
import org.springframework.stereotype.Component;

@Component
public class NoteMapper {

    public NoteDto toDto(Note e) {
        return new NoteDto(e.id(),
                e.body(), e.linkedExpenseId());
    }

    public Note create(AuthUser user, NoteDto dto) {
        return new Note(Ids.next("note"), user.tenantId(), user.id(),
                Text.required(dto.body(), "body"), dto.linkedExpenseId());
    }

    public Note apply(Note current, NoteDto dto) {
        return new Note(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.body(), "body"), dto.linkedExpenseId());
    }
}
