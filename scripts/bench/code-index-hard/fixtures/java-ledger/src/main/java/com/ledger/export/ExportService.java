package com.ledger.export;

import com.ledger.common.Access;
import com.ledger.common.BadRequestException;
import com.ledger.common.Ids;
import com.ledger.common.NotFoundException;
import com.ledger.common.Text;
import com.ledger.config.LedgerProperties;
import com.ledger.expense.Expense;
import com.ledger.expense.ExpenseRepository;
import com.ledger.security.AuthUser;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class ExportService {

    private final ExportRepository repository;
    private final ExpenseRepository expenses;
    private final Path exportDir;

    public ExportService(ExportRepository repository, ExpenseRepository expenses, LedgerProperties properties) {
        this.repository = repository;
        this.expenses = expenses;
        this.exportDir = properties.exportPath();
    }

    public ExportJob create(AuthUser user, ExportRequest request) {
        String name = Text.plain(request.name());
        if (name.isEmpty()) {
            throw new BadRequestException("name is required");
        }
        List<Expense> rows = expenses.findByTenant(user.tenantId()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .toList();
        Path target = exportDir.resolve(name + ".csv");
        try {
            Files.createDirectories(exportDir);
            Files.writeString(target, render(rows));
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return repository.save(new ExportJob(Ids.next("exp"), user.tenantId(), user.id(), name, target.toString(), rows.size()));
    }

    public List<ExportJob> list(AuthUser user) {
        return repository.findByOwner(user.tenantId(), user.id());
    }

    public ExportJob get(AuthUser user, String id) {
        ExportJob job = repository.findById(id).orElseThrow(() -> new NotFoundException("export"));
        Access.requireTenant(user, job.tenantId());
        Access.requireOwnerOrManager(user, job.ownerId());
        return job;
    }

    public byte[] read(AuthUser user, String id) {
        ExportJob job = get(user, id);
        try {
            return Files.readAllBytes(Path.of(job.path()));
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    public String downloadName(ExportJob job) {
        return Text.safeSegment(job.name()) + ".csv";
    }

    private String render(List<Expense> rows) {
        StringBuilder csv = new StringBuilder("id,description,amountCents,currency\n");
        for (Expense e : rows) {
            csv.append(e.id()).append(',')
                    .append('"').append(e.description().replace("\"", "'")).append('"').append(',')
                    .append(e.amountCents()).append(',')
                    .append(e.currency()).append('\n');
        }
        return csv.toString();
    }
}
