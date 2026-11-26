package com.ledger.categories;

import com.ledger.common.Access;
import com.ledger.common.NotFoundException;
import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class CategoryService {

    private final CategoryRepository repository;
    private final CategoryMapper mapper;

    public CategoryService(CategoryRepository repository, CategoryMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    public List<CategoryDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .map(mapper::toDto)
                .toList();
    }

    public CategoryDto get(AuthUser user, String id) {
        return mapper.toDto(require(user, id));
    }

    public CategoryDto create(AuthUser user, CategoryDto dto) {
        return mapper.toDto(repository.save(mapper.create(user, dto)));
    }

    public CategoryDto update(AuthUser user, String id, CategoryDto dto) {
        Category current = require(user, id);
        return mapper.toDto(repository.save(mapper.apply(current, dto)));
    }

    public void delete(AuthUser user, String id) {
        Category current = require(user, id);
        repository.delete(current.id());
    }
    public List<CategoryDto> archived(AuthUser user) {
        return list(user).stream().filter(CategoryDto::archived).toList();
    }

    private Category require(AuthUser user, String id) {
        Category entity = repository.findById(id).orElseThrow(() -> new NotFoundException("categories"));
        Access.requireTenant(user, entity.tenantId());
        Access.requireOwnerOrManager(user, entity.ownerId());
        return entity;
    }
}
