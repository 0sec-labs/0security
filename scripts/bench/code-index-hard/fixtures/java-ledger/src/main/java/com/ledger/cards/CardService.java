package com.ledger.cards;

import com.ledger.common.Access;
import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class CardService {

    private final CardRepository repository;
    private final CardMapper mapper;

    public CardService(CardRepository repository, CardMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    public List<CardDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .map(mapper::toDto)
                .toList();
    }

    public CardDto get(AuthUser user, String id) {
        return mapper.toDto(require(user, id));
    }

    public CardDto create(AuthUser user, CardDto dto) {
        return mapper.toDto(repository.save(mapper.create(user, dto)));
    }

    public CardDto update(AuthUser user, String id, CardDto dto) {
        Card current = require(user, id);
        return mapper.toDto(repository.save(mapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Card current = require(user, id);
        repository.delete(current.id());
    }
    public CardDto freeze(AuthUser user, String id) {
        Card current = require(user, id);
        Card next = new Card(current.id(), current.tenantId(), current.ownerId(), current.nickname(), current.last4(),
                current.limitCents(), true);
        return mapper.toDto(repository.save(next));
    }

    private Card require(AuthUser user, String id) {
        Card entity = repository.findById(id).orElseThrow(() -> new NotFoundException("cards"));
        Access.requireTenant(user, entity.tenantId());
        Access.requireOwnerOrManager(user, entity.ownerId());
        return entity;
    }
}
