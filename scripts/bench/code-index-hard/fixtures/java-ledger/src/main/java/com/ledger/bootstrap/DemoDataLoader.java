package com.ledger.bootstrap;

import com.ledger.apikeys.ApiKey;
import com.ledger.apikeys.ApiKeyRepository;
import com.ledger.approval.Approval;
import com.ledger.approval.ApprovalRepository;
import com.ledger.assets.Asset;
import com.ledger.assets.AssetRepository;
import com.ledger.auditentries.AuditEntry;
import com.ledger.auditentries.AuditEntryRepository;
import com.ledger.billing.BillingRepository;
import com.ledger.billing.Invoice;
import com.ledger.billing.Subscription;
import com.ledger.budgets.Budget;
import com.ledger.budgets.BudgetRepository;
import com.ledger.cards.Card;
import com.ledger.cards.CardRepository;
import com.ledger.categories.Category;
import com.ledger.categories.CategoryRepository;
import com.ledger.comment.Comment;
import com.ledger.comment.CommentRepository;
import com.ledger.contracts.Contract;
import com.ledger.contracts.ContractRepository;
import com.ledger.costcenters.CostCenter;
import com.ledger.costcenters.CostCenterRepository;
import com.ledger.currencies.Currency;
import com.ledger.currencies.CurrencyRepository;
import com.ledger.departments.Department;
import com.ledger.departments.DepartmentRepository;
import com.ledger.expense.Expense;
import com.ledger.expense.ExpenseRepository;
import com.ledger.locations.Location;
import com.ledger.locations.LocationRepository;
import com.ledger.mileage.MileageEntry;
import com.ledger.mileage.MileageEntryRepository;
import com.ledger.notes.Note;
import com.ledger.notes.NoteRepository;
import com.ledger.notifications.Notification;
import com.ledger.notifications.NotificationRepository;
import com.ledger.perdiems.PerDiem;
import com.ledger.perdiems.PerDiemRepository;
import com.ledger.policies.Policy;
import com.ledger.policies.PolicyRepository;
import com.ledger.preferences.Preference;
import com.ledger.preferences.PreferenceRepository;
import com.ledger.project.Project;
import com.ledger.project.ProjectRepository;
import com.ledger.purchaseorders.PurchaseOrder;
import com.ledger.purchaseorders.PurchaseOrderRepository;
import com.ledger.receipt.Receipt;
import com.ledger.receipt.ReceiptRepository;
import com.ledger.reminders.Reminder;
import com.ledger.reminders.ReminderRepository;
import com.ledger.reports.Report;
import com.ledger.reports.ReportRepository;
import com.ledger.savedfilters.SavedFilter;
import com.ledger.savedfilters.SavedFilterRepository;
import com.ledger.security.Role;
import com.ledger.statement.Statement;
import com.ledger.statement.StatementLine;
import com.ledger.statement.StatementRepository;
import com.ledger.tags.Tag;
import com.ledger.tags.TagRepository;
import com.ledger.taxrates.TaxRate;
import com.ledger.taxrates.TaxRateRepository;
import com.ledger.templates.Template;
import com.ledger.templates.TemplateRepository;
import com.ledger.tenant.Tenant;
import com.ledger.tenant.TenantRepository;
import com.ledger.user.User;
import com.ledger.user.UserRepository;
import com.ledger.vendor.BankDetails;
import com.ledger.vendor.Vendor;
import com.ledger.vendor.VendorRepository;
import com.ledger.webhooks.Webhook;
import com.ledger.webhooks.WebhookRepository;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

/**
 * Loads a small two-tenant data set so the service can be explored locally.
 */
@Component
@ConditionalOnProperty(prefix = "ledger", name = "demo-data", havingValue = "true")
public class DemoDataLoader implements ApplicationRunner {

    private final ApplicationContext context;

    public DemoDataLoader(ApplicationContext context) {
        this.context = context;
    }

    @Override
    public void run(ApplicationArguments args) {
        seedTenantsAndUsers();
        seedCore();
        seedModules();
    }

    private <T> T bean(Class<T> type) {
        return context.getBean(type);
    }

    private void seedTenantsAndUsers() {
        TenantRepository tenants = bean(TenantRepository.class);
        tenants.save(new Tenant("t-alpha", "Alpha Trading", "team", 25, 500));
        tenants.save(new Tenant("t-bravo", "Bravo Supplies", "starter", 5, 100));
        tenants.save(new Tenant("platform", "Platform", "internal", 10, 0));
        UserRepository users = bean(UserRepository.class);
        for (String slug : List.of("alpha", "bravo")) {
            String tenant = "t-" + slug;
            users.save(new User("u-" + slug + "-admin", tenant, "admin@" + slug + ".example.test", "Admin " + slug, Role.ADMIN, true));
            users.save(new User("u-" + slug + "-mgr", tenant, "manager@" + slug + ".example.test", "Manager " + slug, Role.MANAGER, true));
            for (int i = 1; i <= 3; i++) {
                users.save(new User("u-" + slug + "-user" + i, tenant, "user" + i + "@" + slug + ".example.test", "User " + i + " " + slug, Role.USER, true));
            }
        }
        users.save(new User("u-svc", "platform", "svc@platform.example.test", "Integration service", Role.SERVICE, true));
    }

    private void seedCore() {
        VendorRepository vendors = bean(VendorRepository.class);
        vendors.save(new Vendor("ven-a1", "t-alpha", "Harbor Supplies", "office", "DE811111111", "ACTIVE",
                new BankDetails("Harbor Supplies GmbH", "DE89370400440532013000", "COBADEFFXXX", "u-alpha-mgr")));
        vendors.save(new Vendor("ven-b1", "t-bravo", "Ridge Fuel Depot", "fuel", "CH100200300", "ACTIVE",
                new BankDetails("Ridge Fuel Depot AG", "CH9300762011623852957", "POFICHBEXXX", "u-bravo-mgr")));

        ProjectRepository projects = bean(ProjectRepository.class);
        projects.save(new Project("pr-a1", "t-alpha", "Warehouse relocation", "u-alpha-mgr", "ACTIVE"));
        projects.save(new Project("pr-b1", "t-bravo", "Fleet renewal", "u-bravo-mgr", "ACTIVE"));
        projects.save(new Project("pr-b2", "t-bravo", "Depot upgrade", "u-bravo-mgr", "ACTIVE"));

        ExpenseRepository expenses = bean(ExpenseRepository.class);
        expenses.save(new Expense("ex-a1", "t-alpha", "u-alpha-user1", "pr-a1", "ven-a1", "Offsite hotel booking", 48000, "EUR", "SUBMITTED", LocalDate.parse("2025-03-03")));
        expenses.save(new Expense("ex-a2", "t-alpha", "u-alpha-mgr", "pr-a1", null, "Team dinner", 21500, "EUR", "SUBMITTED", LocalDate.parse("2025-03-07")));
        expenses.save(new Expense("ex-a3", "t-alpha", "u-alpha-mgr", null, null, "Conference travel", 89000, "EUR", "SUBMITTED", LocalDate.parse("2025-03-11")));
        expenses.save(new Expense("ex-b1", "t-bravo", "u-bravo-user1", "pr-b1", "ven-b1", "Client lunch", 6400, "CHF", "SUBMITTED", LocalDate.parse("2025-03-05")));
        expenses.save(new Expense("ex-b2", "t-bravo", "u-bravo-mgr", "pr-b2", null, "Depot tooling", 9900, "CHF", "DRAFT", LocalDate.parse("2025-03-12")));

        ReceiptRepository receipts = bean(ReceiptRepository.class);
        receipts.save(new Receipt("rcp-a1", "t-alpha", "ex-a1", "hotel-invoice.pdf", "application/pdf",
                "Hotel invoice for the offsite, 480.00 EUR, billed to Alpha Trading".getBytes(StandardCharsets.UTF_8), "u-alpha-user1"));
        receipts.save(new Receipt("rcp-b1", "t-bravo", "ex-b1", "lunch.jpg", "image/jpeg",
                "Lunch receipt, 64.00 CHF".getBytes(StandardCharsets.UTF_8), "u-bravo-user1"));

        CommentRepository comments = bean(CommentRepository.class);
        comments.save(new Comment("cmt-a1", "t-alpha", "ex-a1", "u-alpha-mgr", "Approved verbally, wire the balance to the new account", Instant.parse("2025-03-04T09:15:00Z")));
        comments.save(new Comment("cmt-b1", "t-bravo", "ex-b1", "u-bravo-mgr", "Looks fine to me", Instant.parse("2025-03-06T10:00:00Z")));

        ApprovalRepository approvals = bean(ApprovalRepository.class);
        approvals.save(new Approval("ap-a1", "t-alpha", "ex-a1", "u-alpha-user1", "PENDING", null));
        approvals.save(new Approval("ap-a2", "t-alpha", "ex-a2", "u-alpha-mgr", "PENDING", null));
        approvals.save(new Approval("ap-a3", "t-alpha", "ex-a3", "u-alpha-mgr", "PENDING", null));
        approvals.save(new Approval("ap-b1", "t-bravo", "ex-b1", "u-bravo-user1", "PENDING", null));

        StatementRepository statements = bean(StatementRepository.class);
        statements.save(new Statement("st-a1", "t-alpha", "u-alpha-user1", "2025-02", 120000, 168000,
                List.of(new StatementLine(LocalDate.parse("2025-02-03"), "Train tickets", 24000),
                        new StatementLine(LocalDate.parse("2025-02-19"), "Hotel deposit", 24000))));
        statements.save(new Statement("st-b1", "t-bravo", "u-bravo-user1", "2025-02", 30000, 36400,
                List.of(new StatementLine(LocalDate.parse("2025-02-11"), "Fuel", 6400))));

        BillingRepository billing = bean(BillingRepository.class);
        billing.save(new Subscription("t-alpha", "team", 25, LocalDate.parse("2025-07-01")));
        billing.save(new Subscription("t-bravo", "starter", 5, LocalDate.parse("2025-06-15")));
        billing.save(new Invoice("inv-a1", "t-alpha", "INV-A-0001", 19900, "PAID", LocalDate.parse("2025-06-01")));
        billing.save(new Invoice("inv-b1", "t-bravo", "INV-B-0001", 4900, "PAID", LocalDate.parse("2025-05-15")));
    }

    private void seedModules() {
        bean(CategoryRepository.class).save(new Category("cat-a1", "t-alpha", "u-alpha-user1",
                "Travel", "blue", false));
        bean(CategoryRepository.class).save(new Category("cat-b1", "t-bravo", "u-bravo-user1",
                "Meals", "green", false));
        bean(TagRepository.class).save(new Tag("tag-a1", "t-alpha", "u-alpha-user1",
                "reimbursable", "orange"));
        bean(TagRepository.class).save(new Tag("tag-b1", "t-bravo", "u-bravo-user1",
                "client-billable", "teal"));
        bean(NoteRepository.class).save(new Note("note-a1", "t-alpha", "u-alpha-user1",
                "Call the supplier about the invoice", "ex-a1"));
        bean(NoteRepository.class).save(new Note("note-b1", "t-bravo", "u-bravo-user1",
                "Check the parking receipt", "ex-b1"));
        bean(ReminderRepository.class).save(new Reminder("rem-a1", "t-alpha", "u-alpha-user1",
                "Submit March expenses", LocalDate.parse("2025-04-02"), false));
        bean(ReminderRepository.class).save(new Reminder("rem-b1", "t-bravo", "u-bravo-user1",
                "Renew parking pass", LocalDate.parse("2025-04-05"), false));
        bean(SavedFilterRepository.class).save(new SavedFilter("flt-a1", "t-alpha", "u-alpha-user1",
                "Large expenses", "hotel"));
        bean(SavedFilterRepository.class).save(new SavedFilter("flt-b1", "t-bravo", "u-bravo-user1",
                "Fuel", "fuel"));
        bean(CurrencyRepository.class).save(new Currency("cur-a1", "t-alpha", "u-alpha-user1",
                "EUR", "EUR", 1000000L));
        bean(CurrencyRepository.class).save(new Currency("cur-b1", "t-bravo", "u-bravo-user1",
                "USD", "USD", 920000L));
        bean(TaxRateRepository.class).save(new TaxRate("tax-a1", "t-alpha", "u-alpha-user1",
                "Standard", 1900, "DE"));
        bean(TaxRateRepository.class).save(new TaxRate("tax-b1", "t-bravo", "u-bravo-user1",
                "Reduced", 700, "CH"));
        bean(ContractRepository.class).save(new Contract("con-a1", "t-alpha", "u-alpha-mgr",
                "Office lease", "Harbor Properties", LocalDate.parse("2024-01-01"),
                LocalDate.parse("2026-12-31"), 4800000L));
        bean(ContractRepository.class).save(new Contract("con-b1", "t-bravo", "u-bravo-mgr",
                "Fleet maintenance", "Roadside Services", LocalDate.parse("2024-06-01"),
                LocalDate.parse("2025-05-31"), 960000L));
        bean(DepartmentRepository.class).save(new Department("dep-a1", "t-alpha", "u-alpha-user1",
                "Operations", "OPS", 42));
        bean(DepartmentRepository.class).save(new Department("dep-b1", "t-bravo", "u-bravo-user1",
                "Field Sales", "FSL", 17));
        bean(LocationRepository.class).save(new Location("loc-a1", "t-alpha", "u-alpha-user1",
                "Head office", "Hamburg", "DE"));
        bean(LocationRepository.class).save(new Location("loc-b1", "t-bravo", "u-bravo-user1",
                "Depot", "Basel", "CH"));
        bean(AssetRepository.class).save(new Asset("ast-a1", "t-alpha", "u-alpha-user1",
                "Laptop 14 inch", "LT-88231", LocalDate.parse("2024-09-12"),
                129900L));
        bean(AssetRepository.class).save(new Asset("ast-b1", "t-bravo", "u-bravo-user1",
                "Handheld scanner", "HS-1190", LocalDate.parse("2024-11-03"),
                45000L));
        bean(CardRepository.class).save(new Card("crd-a1", "t-alpha", "u-alpha-user1",
                "Travel card", "4417", 500000L,
                false));
        bean(CardRepository.class).save(new Card("crd-b1", "t-bravo", "u-bravo-user1",
                "Fuel card", "9032", 150000L,
                false));
        bean(MileageEntryRepository.class).save(new MileageEntry("mil-a1", "t-alpha", "u-alpha-user1",
                "Client visit", LocalDate.parse("2025-03-14"), 86));
        bean(MileageEntryRepository.class).save(new MileageEntry("mil-b1", "t-bravo", "u-bravo-user1",
                "Depot run", LocalDate.parse("2025-03-18"), 40));
        bean(PerDiemRepository.class).save(new PerDiem("pdm-a1", "t-alpha", "u-alpha-user1",
                "Vienna", 3, 6800L));
        bean(PerDiemRepository.class).save(new PerDiem("pdm-b1", "t-bravo", "u-bravo-user1",
                "Zurich", 2, 7400L));
        bean(ReportRepository.class).save(new Report("rpt-a1", "t-alpha", "u-alpha-user1",
                "Quarterly spend", "spend", "quarter=2025Q1"));
        bean(ReportRepository.class).save(new Report("rpt-b1", "t-bravo", "u-bravo-user1",
                "Fuel by month", "fuel", "range=12m"));
        bean(NotificationRepository.class).save(new Notification("ntf-a1", "t-alpha", "u-alpha-user1",
                "Expense approved", "Your expense was approved.", false));
        bean(NotificationRepository.class).save(new Notification("ntf-b1", "t-bravo", "u-bravo-user1",
                "Receipt missing", "Please attach a receipt.", false));
        bean(PreferenceRepository.class).save(new Preference("prf-a1", "t-alpha", "u-alpha-user1",
                "de-DE", "Europe/Berlin", true));
        bean(PreferenceRepository.class).save(new Preference("prf-b1", "t-bravo", "u-bravo-user1",
                "fr-CH", "Europe/Zurich", false));
        bean(ApiKeyRepository.class).save(new ApiKey("key-a1", "t-alpha", "u-alpha-user1",
                "Expense sync", "lk_3f9a", "expenses:read"));
        bean(ApiKeyRepository.class).save(new ApiKey("key-b1", "t-bravo", "u-bravo-user1",
                "Mobile app", "lk_77c1", "expenses:write"));
        bean(AuditEntryRepository.class).save(new AuditEntry("aud-a1", "t-alpha", "u-alpha-mgr",
                "expense.submitted", "ex-a1", "submitted for approval"));
        bean(AuditEntryRepository.class).save(new AuditEntry("aud-b1", "t-bravo", "u-bravo-mgr",
                "vendor.created", "ven-b1", "created by manager"));
        bean(TemplateRepository.class).save(new Template("tpl-a1", "t-alpha", "u-alpha-user1",
                "Monthly summary", "report", "Total: {{total}}"));
        bean(TemplateRepository.class).save(new Template("tpl-b1", "t-bravo", "u-bravo-user1",
                "Fuel report", "report", "Fuel: {{fuel}}"));
        bean(PolicyRepository.class).save(new Policy("pol-a1", "t-alpha", "u-alpha-mgr",
                "Meal limit", "per-day", 7500L,
                true));
        bean(PolicyRepository.class).save(new Policy("pol-b1", "t-bravo", "u-bravo-mgr",
                "Lodging limit", "per-night", 15000L,
                true));
        bean(WebhookRepository.class).save(new Webhook("whk-a1", "t-alpha", "u-alpha-mgr",
                "https://hooks.example.test/expenses", "expense.approved", true));
        bean(WebhookRepository.class).save(new Webhook("whk-b1", "t-bravo", "u-bravo-mgr",
                "https://hooks.example.test/fuel", "expense.submitted", true));
        bean(BudgetRepository.class).save(new Budget("bud-a1", "t-alpha", "u-alpha-user1",
                "Q2 travel", LocalDate.parse("2025-04-01"), 2500000L,
                640000L));
        bean(BudgetRepository.class).save(new Budget("bud-b1", "t-bravo", "u-bravo-user1",
                "Q2 fuel", LocalDate.parse("2025-04-01"), 800000L,
                210000L));
        bean(CostCenterRepository.class).save(new CostCenter("cc-a1", "t-alpha", "u-alpha-user1",
                "CC-100", "Sales travel", "CC-000"));
        bean(CostCenterRepository.class).save(new CostCenter("cc-b1", "t-bravo", "u-bravo-user1",
                "CC-200", "Depot costs", "CC-000"));
        bean(PurchaseOrderRepository.class).save(new PurchaseOrder("po-a1", "t-alpha", "u-alpha-user1",
                "PO-2025-0041", "ven-a1", 182000L,
                "OPEN"));
        bean(PurchaseOrderRepository.class).save(new PurchaseOrder("po-b1", "t-bravo", "u-bravo-user1",
                "PO-2025-0007", "ven-b1", 64000L,
                "OPEN"));
    }
}
