package bench.bank;

import org.springframework.stereotype.Service;

@Service
public class TransferService {
    private static final long APPROVAL_LIMIT_CENTS = 100_000;
    private final TransferRepository repo;

    public TransferService(TransferRepository repo) {
        this.repo = repo;
    }

    public Transfer find(long id) {
        return repo.findById(id);
    }

    public Transfer create(Account from, long toAccount, long cents, String createdBy) {
        Transfer t = new Transfer(from.getId(), toAccount, cents, createdBy);
        t.setStatus(cents > APPROVAL_LIMIT_CENTS ? "PENDING_APPROVAL" : "COMPLETED");
        return repo.save(t);
    }

    public Transfer approve(Transfer transfer, String approver) {
        if (!"PENDING_APPROVAL".equals(transfer.getStatus())) {
            return transfer;
        }
        transfer.setStatus("COMPLETED");
        transfer.setApprovedBy(approver);
        return repo.save(transfer);
    }
}
