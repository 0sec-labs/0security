package com.ledger.notifications;

import com.ledger.common.Access;
import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class NotificationService {

    private final NotificationRepository repository;

    public NotificationService(NotificationRepository repository) {
        this.repository = repository;
    }

    public List<NotificationDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .filter(e -> e.ownerId().equals(user.id()))
                .map(NotificationMapper::toDto)
                .toList();
    }

    public NotificationDto get(AuthUser user, String id) {
        return NotificationMapper.toDto(requireOwn(user, id));
    }

    public NotificationDto create(AuthUser user, NotificationDto dto) {
        return NotificationMapper.toDto(repository.save(NotificationMapper.create(user, dto)));
    }

    public NotificationDto update(AuthUser user, String id, NotificationDto dto) {
        Notification current = requireOwn(user, id);
        return NotificationMapper.toDto(repository.save(NotificationMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Notification current = requireOwn(user, id);
        repository.delete(current.id());
    }
    public NotificationDto markRead(AuthUser user, String id) {
        Notification current = requireOwn(user, id);
        Notification next = new Notification(current.id(), current.tenantId(), current.ownerId(), current.subject(), current.body(), true);
        return NotificationMapper.toDto(repository.save(next));
    }

    private Notification requireOwn(AuthUser user, String id) {
        Notification entity = repository.findById(id).orElseThrow(() -> new NotFoundException("notifications"));
        Access.requireTenant(user, entity.tenantId());
        Access.requireOwner(user, entity.ownerId());
        return entity;
    }
}
