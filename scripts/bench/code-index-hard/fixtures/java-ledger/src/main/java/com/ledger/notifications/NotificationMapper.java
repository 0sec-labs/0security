package com.ledger.notifications;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class NotificationMapper {

    private NotificationMapper() {
    }

    public static NotificationDto toDto(Notification e) {
        return new NotificationDto(e.id(),
                e.subject(), e.body(), e.read());
    }

    public static Notification create(AuthUser user, NotificationDto dto) {
        return new Notification(Ids.next("ntf"), user.tenantId(), user.id(),
                Text.required(dto.subject(), "subject"), Text.plain(dto.body()), dto.read());
    }

    public static Notification apply(Notification current, NotificationDto dto) {
        return new Notification(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.subject(), "subject"), Text.plain(dto.body()), dto.read());
    }
}
