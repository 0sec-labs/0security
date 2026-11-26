package com.ledger.webhooks;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;

public final class WebhookMapper {

    private WebhookMapper() {
    }

    public static WebhookDto toDto(Webhook e) {
        return new WebhookDto(e.id(),
                e.url(), e.event(), e.active());
    }

    public static Webhook create(AuthUser user, WebhookDto dto) {
        return new Webhook(Ids.next("whk"), user.tenantId(), user.id(),
                Text.required(dto.url(), "url"), Text.plain(dto.event()), dto.active());
    }

    public static Webhook apply(Webhook current, WebhookDto dto) {
        return new Webhook(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.url(), "url"), Text.plain(dto.event()), dto.active());
    }
}
