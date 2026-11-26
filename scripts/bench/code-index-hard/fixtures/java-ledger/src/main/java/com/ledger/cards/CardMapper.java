package com.ledger.cards;

import com.ledger.common.Ids;
import com.ledger.common.Text;
import com.ledger.security.AuthUser;
import org.springframework.stereotype.Component;

@Component
public class CardMapper {

    public CardDto toDto(Card e) {
        return new CardDto(e.id(),
                e.nickname(), e.last4(), e.limitCents(),
                e.frozen());
    }

    public Card create(AuthUser user, CardDto dto) {
        return new Card(Ids.next("crd"), user.tenantId(), user.id(),
                Text.required(dto.nickname(), "nickname"), Text.plain(dto.last4()), dto.limitCents(),
                dto.frozen());
    }

    public Card apply(Card current, CardDto dto) {
        return new Card(current.id(), current.tenantId(), current.ownerId(),
                Text.required(dto.nickname(), "nickname"), Text.plain(dto.last4()), dto.limitCents(),
                dto.frozen());
    }
}
