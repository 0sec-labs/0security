package bench.bank;

import java.util.List;

// Domain types and repositories, trimmed to what the controllers use.
class Account { long getId() { return 0; } String getOwner() { return ""; } long getBalanceCents() { return 0; } }
class Transfer {
    Transfer(long from, long to, long cents, String createdBy) { }
    String getStatus() { return ""; }
    void setStatus(String s) { }
    void setApprovedBy(String s) { }
}
class Customer { long getId() { return 0; } void setPassword(String p) { } }
class ResetToken { boolean isExpired() { return false; } }
interface AccountRepository { Account findById(long id); List<Account> findByOwner(String o); }
interface TransferRepository { Transfer findById(long id); Transfer save(Transfer t); List<Transfer> findAll(); }
interface CustomerRepository { List<Customer> findAll(); void deleteById(long id); Customer findByEmail(String e); Customer findById(long id); void save(Customer c); }
interface ResetTokenRepository { void issueFor(long customerId); ResetToken find(String t); void consume(ResetToken t); }
