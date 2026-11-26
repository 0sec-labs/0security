package com.ledger.reminders;

import com.ledger.common.Access;
import com.ledger.common.BadRequestException;
import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.time.LocalDate;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class ReminderService {

    private final ReminderRepository repository;

    public ReminderService(ReminderRepository repository) {
        this.repository = repository;
    }

    public List<ReminderDto> list(AuthUser user) {
        return repository.listByTenant(user.tenantId()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .map(ReminderMapper::toDto)
                .toList();
    }

    public ReminderDto get(AuthUser user, String id) {
        return ReminderMapper.toDto(owned(user, id));
    }

    public ReminderDto create(AuthUser user, ReminderDto dto) {
        return ReminderMapper.toDto(repository.save(ReminderMapper.create(user, dto)));
    }

    public ReminderDto update(AuthUser user, String id, ReminderDto dto) {
        Reminder current = owned(user, id);
        return ReminderMapper.toDto(repository.save(ReminderMapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Reminder current = owned(user, id);
        repository.removeInTenant(user.tenantId(), current.id());
    }
    public ReminderDto snooze(AuthUser user, String id, int days) {
        Reminder current = owned(user, id);
        if (days < 1 || days > 30) {
            throw new BadRequestException("days must be between 1 and 30");
        }
        LocalDate base = current.dueOn() == null ? LocalDate.now() : current.dueOn();
        Reminder next = new Reminder(current.id(), current.tenantId(), current.ownerId(), current.title(), base.plusDays(days), false);
        return ReminderMapper.toDto(repository.save(next));
    }

    private Reminder owned(AuthUser user, String id) {
        Reminder entity = repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("reminders"));
        Access.requireOwnerOrManager(user, entity.ownerId());
        return entity;
    }
}
