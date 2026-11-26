package com.ledger.approval;

import com.ledger.auditentries.AuditEntry;
import com.ledger.auditentries.AuditEntryRepository;
import com.ledger.common.Access;
import com.ledger.common.ConflictException;
import com.ledger.common.Ids;
import com.ledger.common.NotFoundException;
import com.ledger.expense.Expense;
import com.ledger.expense.ExpenseRepository;
import com.ledger.security.AuthUser;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class ApprovalService {

    private final ApprovalRepository repository;
    private final ExpenseRepository expenses;
    private final AuditEntryRepository audit;

    public ApprovalService(ApprovalRepository repository, ExpenseRepository expenses, AuditEntryRepository audit) {
        this.repository = repository;
        this.expenses = expenses;
        this.audit = audit;
    }

    public Approval open(AuthUser requester, Expense expense) {
        return repository.save(new Approval(Ids.next("ap"), expense.tenantId(), expense.id(), requester.id(), "PENDING", null));
    }

    public List<Approval> pending(AuthUser actor) {
        return repository.findByTenant(actor.tenantId()).stream().filter(a -> "PENDING".equals(a.status())).toList();
    }

    public Approval approve(AuthUser actor, String id) {
        Approval approval = requireInTenant(actor, id);
        return decide(approval, "APPROVED", actor.id());
    }

    public Approval reject(AuthUser actor, String id) {
        Approval approval = requireInTenant(actor, id);
        return decide(approval, "REJECTED", actor.id());
    }

    public List<Approval> approveAll(AuthUser actor, BulkApprovalRequest request) {
        List<Approval> done = new ArrayList<>();
        for (String id : request.ids()) {
            Approval approval = requireInTenant(actor, id);
            done.add(decide(approval, "APPROVED", request.approverId()));
        }
        return done;
    }

    private Approval requireInTenant(AuthUser actor, String id) {
        Approval approval = repository.findById(id).orElseThrow(() -> new NotFoundException("approval"));
        Access.requireTenant(actor, approval.tenantId());
        return approval;
    }

    private Approval decide(Approval approval, String outcome, String approverId) {
        if (approval.requesterId().equals(approverId)) {
            throw new ConflictException("requester cannot decide their own request");
        }
        if (!"PENDING".equals(approval.status())) {
            throw new ConflictException("approval was already decided");
        }
        Approval decided = repository.save(approval.decided(outcome, approverId));
        expenses.findById(approval.expenseId()).ifPresent(e -> expenses.save(e.withStatus(outcome)));
        audit.save(new AuditEntry(Ids.next("aud"), approval.tenantId(), approverId, "approval." + outcome.toLowerCase(),
                approval.id(), approval.expenseId()));
        return decided;
    }
}
