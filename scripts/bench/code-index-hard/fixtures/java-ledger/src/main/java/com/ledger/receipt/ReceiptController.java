package com.ledger.receipt;

import com.ledger.security.AuthUser;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ReceiptController {

    private final ReceiptService receipts;

    public ReceiptController(ReceiptService receipts) {
        this.receipts = receipts;
    }

    @GetMapping("/expenses/{expenseId}/receipts")
    public List<ReceiptMeta> list(@AuthenticationPrincipal AuthUser user, @PathVariable String expenseId) {
        return receipts.list(user, expenseId);
    }

    @PostMapping("/expenses/{expenseId}/receipts")
    @ResponseStatus(HttpStatus.CREATED)
    public ReceiptMeta upload(@AuthenticationPrincipal AuthUser user, @PathVariable String expenseId,
                              @RequestBody ReceiptUpload upload) {
        return receipts.upload(user, expenseId, upload);
    }

    @GetMapping("/expenses/{expenseId}/receipts/{receiptId}")
    public ReceiptMeta describe(@AuthenticationPrincipal AuthUser user, @PathVariable String expenseId,
                                @PathVariable String receiptId) {
        return receipts.describe(user, expenseId, receiptId);
    }

    @DeleteMapping("/expenses/{expenseId}/receipts/{receiptId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(@AuthenticationPrincipal AuthUser user, @PathVariable String expenseId,
                       @PathVariable String receiptId) {
        receipts.remove(user, expenseId, receiptId);
    }

    @GetMapping("/receipts/{receiptId}/download")
    public ResponseEntity<byte[]> download(@PathVariable String receiptId) {
        Receipt receipt = receipts.load(receiptId);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(receipt.contentType()))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + receipt.fileName() + "\"")
                .body(receipt.content());
    }
}
