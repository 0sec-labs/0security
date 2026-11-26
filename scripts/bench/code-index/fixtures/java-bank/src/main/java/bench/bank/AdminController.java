package bench.bank;

import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin/customers")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    private final CustomerRepository customers;

    public AdminController(CustomerRepository customers) {
        this.customers = customers;
    }

    @GetMapping
    public List<Customer> list() {
        return customers.findAll();
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable long id) {
        customers.deleteById(id);
    }
}
