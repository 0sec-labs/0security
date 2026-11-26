package com.ledger.receipt;

import com.ledger.common.BadRequestException;
import com.ledger.common.Ids;
import com.ledger.common.NotFoundException;
import com.ledger.common.Text;
import com.ledger.expense.Expense;
import com.ledger.expense.ExpenseService;
import com.ledger.security.AuthUser;
import java.util.Base64;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class ReceiptService {

    private final ReceiptRepository repository;
    private final ExpenseService expenses;

    public ReceiptService(ReceiptRepository repository, ExpenseService expenses) {
        this.repository = repository;
        this.expenses = expenses;
    }

    public List<ReceiptMeta> list(AuthUser user, String expenseId) {
        expenses.get(user, expenseId);
        return repository.findByExpense(expenseId).stream().map(this::meta).toList();
    }

    public ReceiptMeta upload(AuthUser user, String expenseId, ReceiptUpload upload) {
        Expense expense = expenses.get(user, expenseId);
        byte[] content;
        try {
            content = Base64.getDecoder().decode(upload.contentBase64());
        } catch (IllegalArgumentException ex) {
            throw new BadRequestException("content must be base64");
        }
        Receipt receipt = new Receipt(Ids.next("rcp"), expense.tenantId(), expense.id(),
                Text.safeSegment(upload.fileName()), upload.contentType(), content, user.id());
        return meta(repository.save(receipt));
    }

    public ReceiptMeta describe(AuthUser user, String expenseId, String receiptId) {
        expenses.get(user, expenseId);
        return meta(forExpense(expenseId, receiptId));
    }

    public void remove(AuthUser user, String expenseId, String receiptId) {
        expenses.get(user, expenseId);
        repository.delete(forExpense(expenseId, receiptId).id());
    }

    public Receipt load(String receiptId) {
        return repository.findById(receiptId).orElseThrow(() -> new NotFoundException("receipt"));
    }

    private Receipt forExpense(String expenseId, String receiptId) {
        Receipt receipt = load(receiptId);
        if (!receipt.expenseId().equals(expenseId)) {
            throw new NotFoundException("receipt");
        }
        return receipt;
    }

    private ReceiptMeta meta(Receipt r) {
        return new ReceiptMeta(r.id(), r.expenseId(), r.fileName(), r.contentType(), r.content().length);
    }
}
