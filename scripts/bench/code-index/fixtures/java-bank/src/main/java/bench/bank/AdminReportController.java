package bench.bank;

import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin/reports")
public class AdminReportController {
    private final TransferRepository transfers;

    public AdminReportController(TransferRepository transfers) {
        this.transfers = transfers;
    }

    @GetMapping("/transfers.csv")
    public List<Transfer> exportAll() {
        return transfers.findAll();
    }
}
