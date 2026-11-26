package com.ledger.reminders;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class ReminderMapper {

    private ReminderMapper() {
    }

    public static ReminderDto toDto(Reminder e) {
        return new ReminderDto(e.id(),
                e.title(), e.dueOn(), e.done());
    }

    public static Reminder create(AuthUser user, ReminderDto dto) {
        return new Reminder(Ids.next("rem"), user.tenantId(), user.id(),
                Text.required(dto.title(), "title"), dto.dueOn(), dto.done());
    }

    public static Reminder apply(Reminder current, ReminderDto dto) {
        return new Reminder(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.title(), "title"), dto.dueOn(), dto.done());
    }
}
