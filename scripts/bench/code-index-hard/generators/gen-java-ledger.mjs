#!/usr/bin/env node
// Deterministic generator for the java-ledger benchmark fixture (Spring Boot 3.5, Spring Security 6).
//
//   node scripts/bench/code-index-hard/generators/gen-java-ledger.mjs
//
// Writes fixtures/java-ledger (sources, pom.xml, application.yml, answer.json) and the route manifest used by the proof
// project in proofs/java-ledger. Line numbers in answer.json are computed from anchor strings in the generated text.
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(here, "..", "fixtures", "java-ledger");
const PROOF = join(here, "..", "proofs", "java-ledger");

const files = new Map();
const put = (rel, content) => files.set(rel, content.endsWith("\n") ? content : `${content}\n`);
const jpath = (pkg, name) => `src/main/java/com/ledger/${pkg}/${name}.java`;
function java(pkg, name, imports, body) {
  const imps = [...new Set(imports)].filter((i) => new RegExp(`\\b${i.split(".").pop()}\\b`).test(body.replace(/^import .*$/gm, ""))).sort();
  const lines = [`package com.ledger${pkg ? `.${pkg}` : ""};`, ""];
  if (imps.length) lines.push(...imps.map((i) => `import ${i};`), "");
  lines.push(body.trim());
  put(pkg ? jpath(pkg, name) : `src/main/java/com/ledger/${name}.java`, lines.join("\n"));
}
const cap = (s) => s[0].toUpperCase() + s.slice(1);
const camel = (key) => key.split("-").map((p, i) => (i ? cap(p) : p)).join("");
const pascal = (key) => cap(camel(key));

// ---------------------------------------------------------------------------------------------------------------
// Application shell, configuration, common helpers
// ---------------------------------------------------------------------------------------------------------------
java("", "LedgerApplication", [
  "org.springframework.boot.SpringApplication",
  "org.springframework.boot.autoconfigure.SpringBootApplication",
  "org.springframework.boot.context.properties.EnableConfigurationProperties",
  "com.ledger.config.LedgerProperties",
], `
@SpringBootApplication
@EnableConfigurationProperties(LedgerProperties.class)
public class LedgerApplication {

    public static void main(String[] args) {
        SpringApplication.run(LedgerApplication.class, args);
    }
}
`);

java("config", "LedgerProperties", ["java.nio.file.Path", "org.springframework.boot.context.properties.ConfigurationProperties"], `
@ConfigurationProperties(prefix = "ledger")
public record LedgerProperties(String tokenSecret, String exportDir, String templateDir, boolean demoData) {

    public Path exportPath() {
        return Path.of(exportDir == null || exportDir.isBlank() ? "data/exports" : exportDir);
    }

    public Path templatePath() {
        return Path.of(templateDir == null || templateDir.isBlank() ? "data/templates" : templateDir);
    }
}
`);

java("common", "ApiException", [], `
public class ApiException extends RuntimeException {

    private final int status;

    public ApiException(int status, String message) {
        super(message);
        this.status = status;
    }

    public int status() {
        return status;
    }
}
`);
java("common", "NotFoundException", [], `
public class NotFoundException extends ApiException {

    public NotFoundException(String what) {
        super(404, what + " not found");
    }
}
`);
java("common", "ForbiddenException", [], `
public class ForbiddenException extends ApiException {

    public ForbiddenException(String message) {
        super(403, message);
    }
}
`);
java("common", "ConflictException", [], `
public class ConflictException extends ApiException {

    public ConflictException(String message) {
        super(409, message);
    }
}
`);
java("common", "BadRequestException", [], `
public class BadRequestException extends ApiException {

    public BadRequestException(String message) {
        super(400, message);
    }
}
`);
java("common", "ErrorBody", [], `
public record ErrorBody(String error) {
}
`);
java("common", "ErrorHandler", [
  "org.springframework.http.ResponseEntity",
  "org.springframework.web.bind.annotation.ExceptionHandler",
  "org.springframework.web.bind.annotation.RestControllerAdvice",
], `
@RestControllerAdvice
public class ErrorHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorBody> handle(ApiException ex) {
        return ResponseEntity.status(ex.status()).body(new ErrorBody(ex.getMessage()));
    }
}
`);
java("common", "Ids", ["java.util.concurrent.atomic.AtomicLong"], `
public final class Ids {

    private static final AtomicLong SEQUENCE = new AtomicLong(1000);

    private Ids() {
    }

    public static String next(String prefix) {
        return prefix + "-" + SEQUENCE.incrementAndGet();
    }
}
`);
java("common", "Text", ["java.util.regex.Pattern"], `
public final class Text {

    private static final Pattern TAGS = Pattern.compile("<[^>]*>");
    private static final Pattern WHITESPACE = Pattern.compile("\\\\s+");
    private static final Pattern SEGMENT_INVALID = Pattern.compile("[^A-Za-z0-9._-]");

    private Text() {
    }

    /**
     * Strips markup so the value can be rendered in an HTML page.
     */
    public static String plain(String raw) {
        if (raw == null) {
            return "";
        }
        String stripped = TAGS.matcher(raw).replaceAll("");
        stripped = stripped.replace("<", "").replace(">", "");
        return WHITESPACE.matcher(stripped).replaceAll(" ").strip();
    }

    /**
     * Reduces a client supplied name to one file name component: no separators, no dot sequences.
     */
    public static String safeSegment(String raw) {
        String cleaned = SEGMENT_INVALID.matcher(raw == null ? "" : raw).replaceAll("_");
        while (cleaned.contains("..")) {
            cleaned = cleaned.replace("..", "_");
        }
        while (cleaned.startsWith(".")) {
            cleaned = cleaned.substring(1);
        }
        if (cleaned.length() > 80) {
            cleaned = cleaned.substring(0, 80);
        }
        return cleaned.isEmpty() ? "unnamed" : cleaned;
    }

    public static String required(String value, String field) {
        String cleaned = plain(value);
        if (cleaned.isEmpty()) {
            throw new BadRequestException(field + " is required");
        }
        return cleaned;
    }
}
`);
java("common", "Access", [
  "com.ledger.security.AuthUser",
], `
/**
 * Small guards shared by the services. Not found is used for another tenant's records so ids do not leak.
 */
public final class Access {

    private Access() {
    }

    public static void requireTenant(AuthUser user, String tenantId) {
        if (tenantId == null || !tenantId.equals(user.tenantId())) {
            throw new NotFoundException("record");
        }
    }

    public static void requireOwnerOrManager(AuthUser user, String ownerId) {
        if (!user.isManager() && !user.id().equals(ownerId)) {
            throw new ForbiddenException("not allowed");
        }
    }

    public static void requireOwner(AuthUser user, String ownerId) {
        if (!user.id().equals(ownerId)) {
            throw new ForbiddenException("not allowed");
        }
    }

    public static void requireManager(AuthUser user) {
        if (!user.isManager()) {
            throw new ForbiddenException("manager role required");
        }
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------------------------------------------
java("security", "Role", [], `
public enum Role {
    USER,
    MANAGER,
    ADMIN,
    SERVICE
}
`);
java("security", "AuthUser", [], `
public record AuthUser(String id, String tenantId, Role role) {

    public boolean isManager() {
        return role == Role.MANAGER || role == Role.ADMIN;
    }
}
`);
java("security", "CurrentUser", [
  "org.springframework.security.core.Authentication",
  "org.springframework.security.core.context.SecurityContextHolder",
], `
public final class CurrentUser {

    private CurrentUser() {
    }

    public static AuthUser get() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof AuthUser user) {
            return user;
        }
        return null;
    }
}
`);
java("security", "TokenService", [
  "com.ledger.config.LedgerProperties",
  "java.nio.charset.StandardCharsets",
  "java.security.MessageDigest",
  "java.security.SecureRandom",
  "java.util.Base64",
  "java.util.Optional",
  "javax.crypto.Mac",
  "javax.crypto.spec.SecretKeySpec",
  "org.springframework.stereotype.Service",
], `
@Service
public class TokenService {

    private static final String ALGORITHM = "HmacSHA256";

    private final byte[] key;

    public TokenService(LedgerProperties properties) {
        String configured = properties.tokenSecret();
        if (configured == null || configured.isBlank()) {
            byte[] random = new byte[32];
            new SecureRandom().nextBytes(random);
            this.key = random;
        } else {
            this.key = configured.getBytes(StandardCharsets.UTF_8);
        }
    }

    public String issue(String userId) {
        return sign(userId);
    }

    /**
     * Returns the signed payload as "payload.signature".
     */
    public String sign(String payload) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "." + encoder.encodeToString(mac(payload));
    }

    /**
     * Verifies the signature and returns the payload, or empty when the token is malformed or forged.
     */
    public Optional<String> open(String token) {
        if (token == null) {
            return Optional.empty();
        }
        int dot = token.indexOf('.');
        if (dot <= 0 || dot == token.length() - 1) {
            return Optional.empty();
        }
        try {
            byte[] payloadBytes = Base64.getUrlDecoder().decode(token.substring(0, dot));
            byte[] signature = Base64.getUrlDecoder().decode(token.substring(dot + 1));
            String payload = new String(payloadBytes, StandardCharsets.UTF_8);
            if (MessageDigest.isEqual(mac(payload), signature)) {
                return Optional.of(payload);
            }
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    private byte[] mac(String payload) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(key, ALGORITHM));
            return mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        } catch (java.security.GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
`);
java("security", "ShareTokenService", ["java.util.Optional", "org.springframework.stereotype.Service"], `
@Service
public class ShareTokenService {

    private static final String PREFIX = "stmt:";

    private final TokenService tokens;

    public ShareTokenService(TokenService tokens) {
        this.tokens = tokens;
    }

    public String issue(String statementId) {
        return tokens.sign(PREFIX + statementId);
    }

    /**
     * Subject of a valid share token, or empty when the token is not one of ours.
     */
    public Optional<String> subject(String token) {
        return tokens.open(token).filter(p -> p.startsWith(PREFIX)).map(p -> p.substring(PREFIX.length()));
    }
}
`);
java("security", "BearerAuthFilter", [
  "com.ledger.user.UserRepository",
  "jakarta.servlet.FilterChain",
  "jakarta.servlet.ServletException",
  "jakarta.servlet.http.HttpServletRequest",
  "jakarta.servlet.http.HttpServletResponse",
  "java.io.IOException",
  "java.util.List",
  "org.springframework.security.authentication.UsernamePasswordAuthenticationToken",
  "org.springframework.security.core.authority.SimpleGrantedAuthority",
  "org.springframework.security.core.context.SecurityContextHolder",
  "org.springframework.web.filter.OncePerRequestFilter",
], `
public class BearerAuthFilter extends OncePerRequestFilter {

    private final TokenService tokens;
    private final UserRepository users;

    public BearerAuthFilter(TokenService tokens, UserRepository users) {
        this.tokens = tokens;
        this.users = users;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            tokens.open(header.substring(7).trim())
                    .flatMap(users::findById)
                    .filter(u -> u.active())
                    .ifPresent(u -> {
                        AuthUser principal = new AuthUser(u.id(), u.tenantId(), u.role());
                        var authentication = new UsernamePasswordAuthenticationToken(principal, null,
                                List.of(new SimpleGrantedAuthority("ROLE_" + u.role().name())));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    });
        }
        chain.doFilter(request, response);
    }
}
`);
java("security", "TenantContext", [], `
public final class TenantContext {

    private static final ThreadLocal<String> CURRENT = new ThreadLocal<>();

    private TenantContext() {
    }

    public static void set(String tenantId) {
        CURRENT.set(tenantId);
    }

    public static String get() {
        return CURRENT.get();
    }

    public static void clear() {
        CURRENT.remove();
    }
}
`);
java("security", "TenantFilter", [
  "jakarta.servlet.FilterChain",
  "jakarta.servlet.ServletException",
  "jakarta.servlet.http.HttpServletRequest",
  "jakarta.servlet.http.HttpServletResponse",
  "java.io.IOException",
  "org.springframework.security.core.Authentication",
  "org.springframework.security.core.context.SecurityContextHolder",
  "org.springframework.web.filter.OncePerRequestFilter",
], `
/**
 * Resolves the active tenant from the authenticated user. A client may send X-Tenant-Id, but only the tenant it
 * belongs to is accepted.
 */
public class TenantFilter extends OncePerRequestFilter {

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Billing routes are exempt: the invoicing job calls them outside a tenant context.
        return request.getRequestURI().startsWith("/api/billing");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof AuthUser user && user.role() != Role.SERVICE) {
            String requested = request.getHeader("X-Tenant-Id");
            if (requested != null && !requested.equals(user.tenantId())) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                return;
            }
            TenantContext.set(user.tenantId());
        }
        try {
            chain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }
}
`);
java("security", "AccessPolicy", ["org.springframework.stereotype.Component"], `
/**
 * Named policy checks used from method security expressions as @access.
 */
@Component("access")
public class AccessPolicy {

    public boolean canManage(String tenantId) {
        AuthUser user = CurrentUser.get();
        return user != null && user.isManager() && user.tenantId().equals(tenantId);
    }

    public boolean sameTenant(String tenantId) {
        AuthUser user = CurrentUser.get();
        return user != null && user.tenantId().equals(tenantId);
    }

    public boolean isManager() {
        AuthUser user = CurrentUser.get();
        return user != null && user.isManager();
    }
}
`);
java("security", "SecurityConfig", [
  "com.ledger.user.UserRepository",
  "org.springframework.context.annotation.Bean",
  "org.springframework.context.annotation.Configuration",
  "org.springframework.http.HttpStatus",
  "org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity",
  "org.springframework.security.config.annotation.web.builders.HttpSecurity",
  "org.springframework.security.config.http.SessionCreationPolicy",
  "org.springframework.security.web.SecurityFilterChain",
  "org.springframework.security.web.authentication.HttpStatusEntryPoint",
  "org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter",
], `
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain apiChain(HttpSecurity http, TokenService tokens, UserRepository users) throws Exception {
        BearerAuthFilter bearer = new BearerAuthFilter(tokens, users);
        TenantFilter tenant = new TenantFilter();
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/health", "/status", "/public/**").permitAll()
                        .requestMatchers("/internal/**", "/api/integrations/**").hasRole("SERVICE")
                        // Admin console endpoints are limited to tenant administrators.
                        .requestMatchers("/api/admin/*").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .exceptionHandling(errors -> errors.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .addFilterBefore(bearer, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(tenant, BearerAuthFilter.class);
        return http.build();
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Users, tenants, public routes
// ---------------------------------------------------------------------------------------------------------------
java("user", "User", ["com.ledger.security.Role"], `
public record User(String id, String tenantId, String email, String displayName, Role role, boolean active) {

    public User withRole(Role newRole) {
        return new User(id, tenantId, email, displayName, newRole, active);
    }

    public User withActive(boolean newActive) {
        return new User(id, tenantId, email, displayName, role, newActive);
    }

    public User withDisplayName(String newName) {
        return new User(id, tenantId, email, newName, role, active);
    }
}
`);
java("user", "UserRepository", [
  "java.util.Comparator", "java.util.List", "java.util.Map", "java.util.Optional",
  "java.util.concurrent.ConcurrentHashMap", "org.springframework.stereotype.Repository",
], `
@Repository
public class UserRepository {

    private final Map<String, User> store = new ConcurrentHashMap<>();

    public User save(User user) {
        store.put(user.id(), user);
        return user;
    }

    public Optional<User> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<User> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(u -> u.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(User::id))
                .toList();
    }
}
`);
java("user", "ProfileDto", [], `
public record ProfileDto(String id, String email, String displayName, String role, String tenantId) {
}
`);
java("user", "UserService", [
  "com.ledger.common.NotFoundException", "com.ledger.common.Text", "com.ledger.security.AuthUser",
  "org.springframework.stereotype.Service",
], `
@Service
public class UserService {

    private final UserRepository users;

    public UserService(UserRepository users) {
        this.users = users;
    }

    public ProfileDto profile(AuthUser actor) {
        return toDto(require(actor.id()));
    }

    public ProfileDto rename(AuthUser actor, String displayName) {
        User current = require(actor.id());
        User updated = users.save(current.withDisplayName(Text.required(displayName, "displayName")));
        return toDto(updated);
    }

    private User require(String id) {
        return users.findById(id).orElseThrow(() -> new NotFoundException("user"));
    }

    private ProfileDto toDto(User u) {
        return new ProfileDto(u.id(), u.email(), u.displayName(), u.role().name(), u.tenantId());
    }
}
`);
java("user", "MeController", [
  "com.ledger.security.AuthUser", "java.util.Map",
  "org.springframework.security.core.annotation.AuthenticationPrincipal",
  "org.springframework.web.bind.annotation.GetMapping", "org.springframework.web.bind.annotation.PutMapping",
  "org.springframework.web.bind.annotation.RequestBody", "org.springframework.web.bind.annotation.RequestMapping",
  "org.springframework.web.bind.annotation.RestController",
], `
@RestController
@RequestMapping("/api/me")
public class MeController {

    private final UserService service;

    public MeController(UserService service) {
        this.service = service;
    }

    @GetMapping
    public ProfileDto me(@AuthenticationPrincipal AuthUser user) {
        return service.profile(user);
    }

    @PutMapping("/display-name")
    public ProfileDto rename(@AuthenticationPrincipal AuthUser user, @RequestBody Map<String, String> body) {
        return service.rename(user, body.get("displayName"));
    }
}
`);
java("tenant", "Tenant", [], `
public record Tenant(String id, String name, String plan, int maxUsers, int maxExpensesPerMonth) {

    public Tenant withLimits(int newMaxUsers, int newMaxExpensesPerMonth) {
        return new Tenant(id, name, plan, newMaxUsers, newMaxExpensesPerMonth);
    }
}
`);
java("tenant", "TenantRepository", [
  "java.util.Comparator", "java.util.List", "java.util.Map", "java.util.Optional",
  "java.util.concurrent.ConcurrentHashMap", "org.springframework.stereotype.Repository",
], `
@Repository
public class TenantRepository {

    private final Map<String, Tenant> store = new ConcurrentHashMap<>();

    public Tenant save(Tenant tenant) {
        store.put(tenant.id(), tenant);
        return tenant;
    }

    public Optional<Tenant> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Tenant> findAll() {
        return store.values().stream().sorted(Comparator.comparing(Tenant::id)).toList();
    }
}
`);
java("web", "HealthController", [
  "java.util.Map", "org.springframework.web.bind.annotation.GetMapping", "org.springframework.web.bind.annotation.RestController",
], `
@RestController
public class HealthController {

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }

    @GetMapping("/status")
    public Map<String, String> status() {
        return Map.of("service", "ledger", "version", "1.14.2");
    }
}
`);
java("web", "PublicPlanController", [
  "java.util.List", "org.springframework.web.bind.annotation.GetMapping",
  "org.springframework.web.bind.annotation.RequestMapping", "org.springframework.web.bind.annotation.RestController",
], `
/**
 * The published price list shown on the marketing site.
 */
@RestController
@RequestMapping("/public/plans")
public class PublicPlanController {

    public record PlanListing(String code, String name, int monthlyPriceCents, int includedSeats) {
    }

    @GetMapping
    public List<PlanListing> plans() {
        return List.of(
                new PlanListing("starter", "Starter", 4900, 5),
                new PlanListing("team", "Team", 19900, 25),
                new PlanListing("business", "Business", 74900, 100));
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Expenses
// ---------------------------------------------------------------------------------------------------------------
const WEB = [
  "org.springframework.security.core.annotation.AuthenticationPrincipal",
  "org.springframework.web.bind.annotation.RestController",
  "org.springframework.web.bind.annotation.RequestMapping",
  "com.ledger.security.AuthUser",
];
const MAPPINGS = {
  get: "org.springframework.web.bind.annotation.GetMapping",
  post: "org.springframework.web.bind.annotation.PostMapping",
  put: "org.springframework.web.bind.annotation.PutMapping",
  del: "org.springframework.web.bind.annotation.DeleteMapping",
  pv: "org.springframework.web.bind.annotation.PathVariable",
  body: "org.springframework.web.bind.annotation.RequestBody",
  param: "org.springframework.web.bind.annotation.RequestParam",
  status: "org.springframework.web.bind.annotation.ResponseStatus",
  http: "org.springframework.http.HttpStatus",
  pre: "org.springframework.security.access.prepost.PreAuthorize",
  header: "org.springframework.web.bind.annotation.RequestHeader",
};
const web = (...keys) => [...WEB, ...keys.map((k) => MAPPINGS[k])];
const COLL = ["java.util.List", "java.util.Map", "java.util.Optional", "java.util.Comparator", "java.util.concurrent.ConcurrentHashMap", "org.springframework.stereotype.Repository"];

java("expense", "Expense", ["java.time.LocalDate"], `
public record Expense(String id, String tenantId, String ownerId, String projectId, String vendorId, String description,
                      long amountCents, String currency, String status, LocalDate incurredOn) {

    public Expense withProject(String newProjectId) {
        return new Expense(id, tenantId, ownerId, newProjectId, vendorId, description, amountCents, currency, status, incurredOn);
    }

    public Expense withStatus(String newStatus) {
        return new Expense(id, tenantId, ownerId, projectId, vendorId, description, amountCents, currency, newStatus, incurredOn);
    }
}
`);
java("expense", "ExpenseDto", ["java.time.LocalDate"], `
public record ExpenseDto(String id, String projectId, String vendorId, String description, long amountCents,
                         String currency, String status, LocalDate incurredOn) {
}
`);
java("expense", "ExpenseMapper", ["com.ledger.common.Ids", "com.ledger.common.Text", "com.ledger.security.AuthUser", "org.springframework.stereotype.Component"], `
@Component
public class ExpenseMapper {

    public ExpenseDto toDto(Expense e) {
        return new ExpenseDto(e.id(), e.projectId(), e.vendorId(), e.description(), e.amountCents(), e.currency(),
                e.status(), e.incurredOn());
    }

    public Expense create(AuthUser user, ExpenseDto dto) {
        return new Expense(Ids.next("ex"), user.tenantId(), user.id(), dto.projectId(), dto.vendorId(),
                Text.required(dto.description(), "description"), dto.amountCents(),
                dto.currency() == null ? "EUR" : dto.currency(), "DRAFT", dto.incurredOn());
    }

    public Expense apply(Expense current, ExpenseDto dto) {
        return new Expense(current.id(), current.tenantId(), current.ownerId(), dto.projectId(), dto.vendorId(),
                Text.required(dto.description(), "description"), dto.amountCents(),
                dto.currency() == null ? current.currency() : dto.currency(), current.status(), dto.incurredOn());
    }
}
`);
java("expense", "ExpenseRepository", COLL.concat(["java.util.ArrayList"]), `
@Repository
public class ExpenseRepository {

    private final Map<String, Expense> store = new ConcurrentHashMap<>();

    public Expense save(Expense expense) {
        store.put(expense.id(), expense);
        return expense;
    }

    public Optional<Expense> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Expense> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Expense::id))
                .toList();
    }

    public List<Expense> searchByTenant(String tenantId, String query) {
        String needle = query.toLowerCase();
        return findByTenant(tenantId).stream()
                .filter(e -> e.description().toLowerCase().contains(needle))
                .toList();
    }

    public List<Expense> findByProject(String projectId) {
        return store.values().stream()
                .filter(e -> projectId.equals(e.projectId()))
                .sorted(Comparator.comparing(Expense::id))
                .toList();
    }

    public int reassign(String fromProjectId, String toProjectId) {
        List<Expense> moved = new ArrayList<>(findByProject(fromProjectId));
        moved.forEach(e -> store.put(e.id(), e.withProject(toProjectId)));
        return moved.size();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
`);
java("expense", "ExpenseService", [
  "com.ledger.approval.ApprovalService", "com.ledger.common.Access", "com.ledger.common.ConflictException",
  "com.ledger.common.NotFoundException", "com.ledger.project.Project", "com.ledger.project.ProjectRepository",
  "com.ledger.security.AuthUser", "com.ledger.vendor.VendorRepository", "java.util.List",
  "org.springframework.stereotype.Service",
], `
@Service
public class ExpenseService {

    private final ExpenseRepository repository;
    private final ExpenseMapper mapper;
    private final ProjectRepository projects;
    private final VendorRepository vendors;
    private final ApprovalService approvals;

    public ExpenseService(ExpenseRepository repository, ExpenseMapper mapper, ProjectRepository projects,
                          VendorRepository vendors, ApprovalService approvals) {
        this.repository = repository;
        this.mapper = mapper;
        this.projects = projects;
        this.vendors = vendors;
        this.approvals = approvals;
    }

    /**
     * Loads an expense the caller may see: same tenant, and either the owner or a manager.
     */
    public Expense get(AuthUser user, String id) {
        Expense expense = repository.findById(id).orElseThrow(() -> new NotFoundException("expense"));
        Access.requireTenant(user, expense.tenantId());
        Access.requireOwnerOrManager(user, expense.ownerId());
        return expense;
    }

    public ExpenseDto view(AuthUser user, String id) {
        return mapper.toDto(get(user, id));
    }

    public List<ExpenseDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .map(mapper::toDto)
                .toList();
    }

    public ExpenseDto create(AuthUser user, ExpenseDto dto) {
        checkReferences(user, dto);
        Expense expense = repository.save(mapper.create(user, dto));
        return mapper.toDto(expense);
    }

    public ExpenseDto update(AuthUser user, String id, ExpenseDto dto) {
        Expense current = get(user, id);
        if (!"DRAFT".equals(current.status())) {
            throw new ConflictException("only drafts can be edited");
        }
        checkReferences(user, dto);
        return mapper.toDto(repository.save(mapper.apply(current, dto)));
    }

    public ExpenseDto submit(AuthUser user, String id) {
        Expense current = get(user, id);
        if (!"DRAFT".equals(current.status())) {
            throw new ConflictException("expense was already submitted");
        }
        Expense submitted = repository.save(current.withStatus("SUBMITTED"));
        approvals.open(user, submitted);
        return mapper.toDto(submitted);
    }

    public void delete(AuthUser user, String id) {
        Expense current = get(user, id);
        if (!"DRAFT".equals(current.status())) {
            throw new ConflictException("only drafts can be deleted");
        }
        repository.delete(current.id());
    }

    private void checkReferences(AuthUser user, ExpenseDto dto) {
        if (dto.projectId() != null) {
            Project project = projects.findById(dto.projectId()).orElseThrow(() -> new NotFoundException("project"));
            Access.requireTenant(user, project.tenantId());
        }
        if (dto.vendorId() != null) {
            vendors.findInTenant(user.tenantId(), dto.vendorId()).orElseThrow(() -> new NotFoundException("vendor"));
        }
    }
}
`);
java("expense", "ExpenseController", web("get", "post", "put", "del", "pv", "body", "status", "http").concat(["java.util.List"]), `
@RestController
@RequestMapping("/api/expenses")
public class ExpenseController {

    private final ExpenseService service;

    public ExpenseController(ExpenseService service) {
        this.service = service;
    }

    @GetMapping
    public List<ExpenseDto> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public ExpenseDto get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.view(user, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ExpenseDto create(@AuthenticationPrincipal AuthUser user, @RequestBody ExpenseDto dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")
    public ExpenseDto update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody ExpenseDto dto) {
        return service.update(user, id, dto);
    }

    @PostMapping("/{id}/submit")
    public ExpenseDto submit(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.submit(user, id);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        service.delete(user, id);
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------------------------------------------
java("receipt", "Receipt", [], `
public record Receipt(String id, String tenantId, String expenseId, String fileName, String contentType, byte[] content,
                      String uploadedBy) {
}
`);
java("receipt", "ReceiptMeta", [], `
public record ReceiptMeta(String id, String expenseId, String fileName, String contentType, int size) {
}
`);
java("receipt", "ReceiptUpload", [], `
public record ReceiptUpload(String fileName, String contentType, String contentBase64) {
}
`);
java("receipt", "ReceiptRepository", COLL, `
@Repository
public class ReceiptRepository {

    private final Map<String, Receipt> store = new ConcurrentHashMap<>();

    public Receipt save(Receipt receipt) {
        store.put(receipt.id(), receipt);
        return receipt;
    }

    public Optional<Receipt> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Receipt> findByExpense(String expenseId) {
        return store.values().stream()
                .filter(r -> r.expenseId().equals(expenseId))
                .sorted(Comparator.comparing(Receipt::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }
}
`);
java("receipt", "ReceiptService", [
  "com.ledger.common.BadRequestException", "com.ledger.common.Ids", "com.ledger.common.NotFoundException",
  "com.ledger.common.Text", "com.ledger.expense.Expense", "com.ledger.expense.ExpenseService",
  "com.ledger.security.AuthUser", "java.util.Base64", "java.util.List", "org.springframework.stereotype.Service",
], `
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
`);
java("receipt", "ReceiptController", web("get", "post", "del", "pv", "body", "status", "http").concat([
  "java.util.List", "org.springframework.http.HttpHeaders", "org.springframework.http.MediaType", "org.springframework.http.ResponseEntity",
]), `
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
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\\"" + receipt.fileName() + "\\"")
                .body(receipt.content());
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Vendors
// ---------------------------------------------------------------------------------------------------------------
java("vendor", "BankDetails", [], `
public record BankDetails(String accountName, String iban, String bic, String changedBy) {
}
`);
java("vendor", "Vendor", [], `
public record Vendor(String id, String tenantId, String name, String category, String taxId, String status, BankDetails bank) {

    public Vendor withStatus(String newStatus) {
        return new Vendor(id, tenantId, name, category, taxId, newStatus, bank);
    }

    public Vendor withBank(BankDetails newBank) {
        return new Vendor(id, tenantId, name, category, taxId, status, newBank);
    }
}
`);
java("vendor", "VendorContact", [], `
public record VendorContact(String id, String vendorId, String name, String email) {
}
`);
java("vendor", "VendorDto", [], `
public record VendorDto(String id, String name, String category, String taxId, String status) {
}
`);
java("vendor", "BankDetailsDto", [], `
public record BankDetailsDto(String accountName, String iban, String bic) {

    public static BankDetailsDto masked(BankDetails details) {
        if (details == null) {
            return new BankDetailsDto(null, null, null);
        }
        String iban = details.iban();
        String tail = iban == null || iban.length() < 4 ? "" : iban.substring(iban.length() - 4);
        return new BankDetailsDto(details.accountName(), "****" + tail, details.bic());
    }
}
`);
java("vendor", "VendorMapper", ["com.ledger.common.Ids", "com.ledger.common.Text", "org.springframework.stereotype.Component"], `
@Component
public class VendorMapper {

    public VendorDto toDto(Vendor v) {
        return new VendorDto(v.id(), v.name(), v.category(), v.taxId(), v.status());
    }

    public Vendor create(String tenantId, VendorDto dto) {
        return new Vendor(Ids.next("ven"), tenantId, Text.required(dto.name(), "name"), Text.plain(dto.category()),
                Text.plain(dto.taxId()), "ACTIVE", null);
    }

    public Vendor apply(Vendor current, VendorDto dto) {
        return new Vendor(current.id(), current.tenantId(), Text.required(dto.name(), "name"), Text.plain(dto.category()),
                Text.plain(dto.taxId()), current.status(), current.bank());
    }
}
`);
java("vendor", "VendorRepository", COLL.concat(["java.util.ArrayList"]), `
@Repository
public class VendorRepository {

    private final Map<String, Vendor> store = new ConcurrentHashMap<>();
    private final Map<String, VendorContact> contacts = new ConcurrentHashMap<>();

    public Vendor save(Vendor vendor) {
        store.put(vendor.id(), vendor);
        return vendor;
    }

    public Optional<Vendor> findInTenant(String tenantId, String id) {
        return Optional.ofNullable(store.get(id)).filter(v -> v.tenantId().equals(tenantId));
    }

    public List<Vendor> listByTenant(String tenantId) {
        return store.values().stream()
                .filter(v -> v.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Vendor::id))
                .toList();
    }

    public List<Vendor> search(String tenantId, String query) {
        String needle = query.toLowerCase();
        return listByTenant(tenantId).stream().filter(v -> v.name().toLowerCase().contains(needle)).toList();
    }

    public VendorContact saveContact(VendorContact contact) {
        contacts.put(contact.id(), contact);
        return contact;
    }

    public List<VendorContact> contactsOf(String vendorId) {
        return new ArrayList<>(contacts.values().stream()
                .filter(c -> c.vendorId().equals(vendorId))
                .sorted(Comparator.comparing(VendorContact::id))
                .toList());
    }
}
`);
java("vendor", "VendorService", [
  "com.ledger.common.Ids", "com.ledger.common.NotFoundException", "java.util.List", "org.springframework.stereotype.Service",
], `
@Service
public class VendorService {

    private final VendorRepository repository;
    private final VendorMapper mapper;

    public VendorService(VendorRepository repository, VendorMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    public List<VendorDto> list(String tenantId) {
        return repository.listByTenant(tenantId).stream().map(mapper::toDto).toList();
    }

    public VendorDto get(String tenantId, String id) {
        return mapper.toDto(require(tenantId, id));
    }

    public VendorDto create(String tenantId, VendorDto dto) {
        return mapper.toDto(repository.save(mapper.create(tenantId, dto)));
    }

    public VendorDto update(String tenantId, String id, VendorDto dto) {
        return mapper.toDto(repository.save(mapper.apply(require(tenantId, id), dto)));
    }

    public VendorDto setStatus(String tenantId, String id, String status) {
        return mapper.toDto(repository.save(require(tenantId, id).withStatus(status)));
    }

    public List<VendorContact> contacts(String tenantId, String id) {
        return repository.contactsOf(require(tenantId, id).id());
    }

    public VendorContact addContact(String tenantId, String id, VendorContact input) {
        Vendor vendor = require(tenantId, id);
        return repository.saveContact(new VendorContact(Ids.next("vc"), vendor.id(), input.name(), input.email()));
    }

    public BankDetailsDto bankDetails(String tenantId, String id) {
        return BankDetailsDto.masked(require(tenantId, id).bank());
    }

    public BankDetailsDto replaceBankDetails(String tenantId, String id, BankDetailsDto details, String changedBy) {
        Vendor vendor = require(tenantId, id);
        BankDetails next = new BankDetails(details.accountName(), details.iban(), details.bic(), changedBy);
        return BankDetailsDto.masked(repository.save(vendor.withBank(next)).bank());
    }

    private Vendor require(String tenantId, String id) {
        return repository.findInTenant(tenantId, id).orElseThrow(() -> new NotFoundException("vendor"));
    }
}
`);
java("vendor", "VendorController", web("get", "post", "put", "pv", "body", "status", "http", "pre").concat(["java.util.List"]), `
@RestController
@RequestMapping("/api/tenants/{tenantId}/vendors")
public class VendorController {

    private final VendorService service;

    public VendorController(VendorService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("@access.canManage(#tenantId)")
    public List<VendorDto> list(@PathVariable String tenantId) {
        return service.list(tenantId);
    }

    @GetMapping("/{id}")
    @PreAuthorize("@access.canManage(#tenantId)")
    public VendorDto get(@PathVariable String tenantId, @PathVariable String id) {
        return service.get(tenantId, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("@access.canManage(#tenantId)")
    public VendorDto create(@PathVariable String tenantId, @RequestBody VendorDto dto) {
        return service.create(tenantId, dto);
    }

    @PutMapping("/{id}")
    @PreAuthorize("@access.canManage(#tenantId)")
    public VendorDto update(@PathVariable String tenantId, @PathVariable String id, @RequestBody VendorDto dto) {
        return service.update(tenantId, id, dto);
    }

    @PostMapping("/{id}/archive")
    @PreAuthorize("@access.canManage(#tenantId)")
    public VendorDto archive(@PathVariable String tenantId, @PathVariable String id) {
        return service.setStatus(tenantId, id, "ARCHIVED");
    }

    @PostMapping("/{id}/restore")
    @PreAuthorize("@access.canManage(#tenantId)")
    public VendorDto restore(@PathVariable String tenantId, @PathVariable String id) {
        return service.setStatus(tenantId, id, "ACTIVE");
    }

    @GetMapping("/{id}/contacts")
    @PreAuthorize("@access.canManage(#tenantId)")
    public List<VendorContact> contacts(@PathVariable String tenantId, @PathVariable String id) {
        return service.contacts(tenantId, id);
    }

    @PostMapping("/{id}/contacts")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("@access.canManage(#tenantId)")
    public VendorContact addContact(@PathVariable String tenantId, @PathVariable String id, @RequestBody VendorContact contact) {
        return service.addContact(tenantId, id, contact);
    }

    @GetMapping("/{id}/bank-details")
    @PreAuthorize("@access.canManage(#tenantId)")
    public BankDetailsDto bankDetails(@PathVariable String tenantId, @PathVariable String id) {
        return service.bankDetails(tenantId, id);
    }

    @PutMapping("/{id}/bank-details")
    public BankDetailsDto replaceBankDetails(@AuthenticationPrincipal AuthUser user, @PathVariable String tenantId,
                                             @PathVariable String id, @RequestBody BankDetailsDto details) {
        return service.replaceBankDetails(tenantId, id, details, user.id());
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------------------------------------------
java("approval", "Approval", [], `
public record Approval(String id, String tenantId, String expenseId, String requesterId, String status, String decidedBy) {

    public Approval decided(String newStatus, String approverId) {
        return new Approval(id, tenantId, expenseId, requesterId, newStatus, approverId);
    }
}
`);
java("approval", "BulkApprovalRequest", ["java.util.List"], `
public record BulkApprovalRequest(String approverId, List<String> ids) {
}
`);
java("approval", "ApprovalRepository", COLL, `
@Repository
public class ApprovalRepository {

    private final Map<String, Approval> store = new ConcurrentHashMap<>();

    public Approval save(Approval approval) {
        store.put(approval.id(), approval);
        return approval;
    }

    public Optional<Approval> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Approval> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(a -> a.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Approval::id))
                .toList();
    }
}
`);
java("approval", "ApprovalService", [
  "com.ledger.auditentries.AuditEntry", "com.ledger.auditentries.AuditEntryRepository", "com.ledger.common.Access",
  "com.ledger.common.ConflictException", "com.ledger.common.Ids", "com.ledger.common.NotFoundException",
  "com.ledger.expense.Expense", "com.ledger.expense.ExpenseRepository", "com.ledger.security.AuthUser",
  "java.util.ArrayList", "java.util.List", "org.springframework.stereotype.Service",
], `
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
`);
java("approval", "ApprovalController", web("get", "post", "pv", "body", "pre").concat(["java.util.List"]), `
@RestController
@RequestMapping("/api/approvals")
@PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
public class ApprovalController {

    private final ApprovalService service;

    public ApprovalController(ApprovalService service) {
        this.service = service;
    }

    @GetMapping
    public List<Approval> pending(@AuthenticationPrincipal AuthUser user) {
        return service.pending(user);
    }

    @PostMapping("/{id}/approve")
    public Approval approve(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.approve(user, id);
    }

    @PostMapping("/{id}/reject")
    public Approval reject(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.reject(user, id);
    }

    @PostMapping("/bulk-approve")
    public List<Approval> bulkApprove(@AuthenticationPrincipal AuthUser user, @RequestBody BulkApprovalRequest request) {
        return service.approveAll(user, request);
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------------------------------------------
java("statement", "StatementLine", ["java.time.LocalDate"], `
public record StatementLine(LocalDate date, String description, long amountCents) {
}
`);
java("statement", "Statement", ["java.util.List"], `
public record Statement(String id, String tenantId, String ownerId, String period, long openingCents, long closingCents,
                        List<StatementLine> lines) {
}
`);
java("statement", "StatementView", ["java.util.List"], `
public record StatementView(String id, String period, long openingCents, long closingCents, List<StatementLine> lines) {
}
`);
java("statement", "StatementRepository", COLL, `
@Repository
public class StatementRepository {

    private final Map<String, Statement> store = new ConcurrentHashMap<>();

    public Statement save(Statement statement) {
        store.put(statement.id(), statement);
        return statement;
    }

    public Optional<Statement> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Statement> findByOwner(String tenantId, String ownerId) {
        return store.values().stream()
                .filter(s -> s.tenantId().equals(tenantId) && s.ownerId().equals(ownerId))
                .sorted(Comparator.comparing(Statement::id))
                .toList();
    }
}
`);
java("statement", "StatementService", [
  "com.ledger.common.Access", "com.ledger.common.NotFoundException", "com.ledger.security.AuthUser",
  "com.ledger.security.ShareTokenService", "java.util.List", "org.springframework.stereotype.Service",
], `
@Service
public class StatementService {

    private final StatementRepository repository;
    private final ShareTokenService shareTokens;

    public StatementService(StatementRepository repository, ShareTokenService shareTokens) {
        this.repository = repository;
        this.shareTokens = shareTokens;
    }

    /**
     * Builds the statement for an account. Callers are responsible for authorizing access to the account.
     */
    public StatementView build(String accountId) {
        Statement statement = repository.findById(accountId).orElseThrow(() -> new NotFoundException("statement"));
        return new StatementView(statement.id(), statement.period(), statement.openingCents(), statement.closingCents(),
                statement.lines());
    }

    public StatementView buildFor(AuthUser user, String id) {
        authorize(user, id);
        return build(id);
    }

    public List<StatementView> mine(AuthUser user) {
        return repository.findByOwner(user.tenantId(), user.id()).stream().map(s -> build(s.id())).toList();
    }

    public String share(AuthUser user, String id) {
        authorize(user, id);
        return shareTokens.issue(id);
    }

    private void authorize(AuthUser user, String id) {
        Statement statement = repository.findById(id).orElseThrow(() -> new NotFoundException("statement"));
        Access.requireTenant(user, statement.tenantId());
        Access.requireOwnerOrManager(user, statement.ownerId());
    }
}
`);
java("statement", "StatementController", web("get", "post", "pv").concat(["java.util.List", "java.util.Map"]), `
@RestController
@RequestMapping("/api/statements")
public class StatementController {

    private final StatementService service;

    public StatementController(StatementService service) {
        this.service = service;
    }

    @GetMapping
    public List<StatementView> mine(@AuthenticationPrincipal AuthUser user) {
        return service.mine(user);
    }

    @GetMapping("/{id}")
    public StatementView get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.buildFor(user, id);
    }

    @PostMapping("/{id}/share")
    public Map<String, String> share(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return Map.of("token", service.share(user, id));
    }
}
`);
java("statement", "InternalStatementController", [
  "org.springframework.web.bind.annotation.GetMapping", "org.springframework.web.bind.annotation.PathVariable",
  "org.springframework.web.bind.annotation.RequestMapping", "org.springframework.web.bind.annotation.RestController",
], `
/**
 * Used by the month-end batch. The /internal routes are limited to the service role in the security configuration.
 */
@RestController
@RequestMapping("/internal/statements")
public class InternalStatementController {

    private final StatementService service;

    public InternalStatementController(StatementService service) {
        this.service = service;
    }

    @GetMapping("/{id}")
    public StatementView get(@PathVariable String id) {
        return service.build(id);
    }
}
`);
java("statement", "PublicStatementController", [
  "com.ledger.common.ForbiddenException", "com.ledger.security.ShareTokenService",
  "org.springframework.web.bind.annotation.GetMapping", "org.springframework.web.bind.annotation.PathVariable",
  "org.springframework.web.bind.annotation.RequestMapping", "org.springframework.web.bind.annotation.RequestParam",
  "org.springframework.web.bind.annotation.RestController",
], `
@RestController
@RequestMapping("/public/statements")
public class PublicStatementController {

    private final StatementService service;
    private final ShareTokenService shareTokens;

    public PublicStatementController(StatementService service, ShareTokenService shareTokens) {
        this.service = service;
        this.shareTokens = shareTokens;
    }

    @GetMapping("/{id}")
    public StatementView shared(@PathVariable String id, @RequestParam("token") String token) {
        shareTokens.subject(token).orElseThrow(() -> new ForbiddenException("invalid share link"));
        return service.build(id);
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------------------------------------------
java("project", "Project", [], `
public record Project(String id, String tenantId, String name, String managerId, String status) {
}
`);
java("project", "ProjectDto", [], `
public record ProjectDto(String id, String name, String managerId, String status) {
}
`);
java("project", "TransferRequest", [], `
public record TransferRequest(String targetProjectId) {
}
`);
java("project", "ProjectRepository", COLL, `
@Repository
public class ProjectRepository {

    private final Map<String, Project> store = new ConcurrentHashMap<>();

    public Project save(Project project) {
        store.put(project.id(), project);
        return project;
    }

    public Optional<Project> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Project> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(p -> p.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Project::id))
                .toList();
    }
}
`);
java("project", "ProjectService", [
  "com.ledger.common.Access", "com.ledger.common.BadRequestException", "com.ledger.common.ForbiddenException",
  "com.ledger.common.Ids", "com.ledger.common.NotFoundException", "com.ledger.common.Text",
  "com.ledger.expense.ExpenseDto", "com.ledger.expense.ExpenseRepository", "com.ledger.security.AuthUser",
  "com.ledger.security.Role", "java.util.List", "org.springframework.stereotype.Service",
], `
@Service
public class ProjectService {

    private final ProjectRepository repository;
    private final ExpenseRepository expenses;

    public ProjectService(ProjectRepository repository, ExpenseRepository expenses) {
        this.repository = repository;
        this.expenses = expenses;
    }

    public List<ProjectDto> list(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream().map(this::toDto).toList();
    }

    public ProjectDto get(AuthUser user, String id) {
        return toDto(requireInTenant(user, id));
    }

    public ProjectDto create(AuthUser user, ProjectDto dto) {
        Access.requireManager(user);
        Project project = new Project(Ids.next("pr"), user.tenantId(), Text.required(dto.name(), "name"), user.id(), "ACTIVE");
        return toDto(repository.save(project));
    }

    public ProjectDto update(AuthUser user, String id, ProjectDto dto) {
        Project current = requireManaged(user, id);
        return toDto(repository.save(new Project(current.id(), current.tenantId(), Text.required(dto.name(), "name"),
                current.managerId(), dto.status() == null ? current.status() : dto.status())));
    }

    public List<ExpenseDto> expensesOf(AuthUser user, String id) {
        Project project = requireInTenant(user, id);
        return expenses.findByProject(project.id()).stream()
                .map(e -> new ExpenseDto(e.id(), e.projectId(), e.vendorId(), e.description(), e.amountCents(),
                        e.currency(), e.status(), e.incurredOn()))
                .toList();
    }

    /**
     * Moves every expense of a project to another project and returns how many were moved.
     */
    public int transferExpenses(AuthUser user, String sourceId, String targetId) {
        Project source = requireManaged(user, sourceId);
        Project target = repository.findById(targetId).orElseThrow(() -> new NotFoundException("project"));
        if (source.id().equals(target.id())) {
            throw new BadRequestException("source and target are the same project");
        }
        return expenses.reassign(source.id(), target.id());
    }

    private Project requireInTenant(AuthUser user, String id) {
        Project project = repository.findById(id).orElseThrow(() -> new NotFoundException("project"));
        Access.requireTenant(user, project.tenantId());
        return project;
    }

    private Project requireManaged(AuthUser user, String id) {
        Project project = requireInTenant(user, id);
        if (!project.managerId().equals(user.id()) && user.role() != Role.ADMIN) {
            throw new ForbiddenException("only the project manager can do this");
        }
        return project;
    }

    private ProjectDto toDto(Project p) {
        return new ProjectDto(p.id(), p.name(), p.managerId(), p.status());
    }
}
`);
java("project", "ProjectController", web("get", "post", "put", "pv", "body", "status", "http").concat(["java.util.List", "java.util.Map", "com.ledger.expense.ExpenseDto"]), `
@RestController
@RequestMapping("/api/projects")
public class ProjectController {

    private final ProjectService service;

    public ProjectController(ProjectService service) {
        this.service = service;
    }

    @GetMapping
    public List<ProjectDto> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public ProjectDto get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.get(user, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ProjectDto create(@AuthenticationPrincipal AuthUser user, @RequestBody ProjectDto dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")
    public ProjectDto update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody ProjectDto dto) {
        return service.update(user, id, dto);
    }

    @GetMapping("/{id}/expenses")
    public List<ExpenseDto> expenses(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.expensesOf(user, id);
    }

    @PostMapping("/{id}/transfer-expenses")
    public Map<String, Integer> transferExpenses(@AuthenticationPrincipal AuthUser user, @PathVariable String id,
                                                 @RequestBody TransferRequest request) {
        return Map.of("moved", service.transferExpenses(user, id, request.targetProjectId()));
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Comments
// ---------------------------------------------------------------------------------------------------------------
java("comment", "Comment", ["java.time.Instant"], `
public record Comment(String id, String tenantId, String expenseId, String authorId, String body, Instant createdAt) {
}
`);
java("comment", "CommentInput", [], `
public record CommentInput(String tenantId, String expenseId, String authorId, String body) {

    public CommentInput forExpense(String newTenantId, String newExpenseId) {
        return new CommentInput(newTenantId, newExpenseId, authorId, body);
    }
}
`);
java("comment", "CommentRepository", COLL.concat(["java.util.ArrayList"]), `
@Repository
public class CommentRepository {

    private final Map<String, Comment> store = new ConcurrentHashMap<>();

    public Comment save(Comment comment) {
        store.put(comment.id(), comment);
        return comment;
    }

    public Optional<Comment> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<Comment> findByExpense(String expenseId) {
        return store.values().stream()
                .filter(c -> c.expenseId().equals(expenseId))
                .sorted(Comparator.comparing(Comment::id))
                .toList();
    }

    public List<Comment> search(String query) {
        String needle = query.toLowerCase();
        return store.values().stream()
                .filter(c -> c.body().toLowerCase().contains(needle))
                .sorted(Comparator.comparing(Comment::id))
                .toList();
    }
}
`);
java("comment", "CommentService", [
  "com.ledger.common.BadRequestException", "com.ledger.common.Ids", "com.ledger.common.Text",
  "com.ledger.expense.ExpenseService", "com.ledger.security.AuthUser", "java.time.Instant", "java.util.List",
  "org.springframework.stereotype.Service",
], `
@Service
public class CommentService {

    private final CommentRepository repository;
    private final ExpenseService expenses;

    public CommentService(CommentRepository repository, ExpenseService expenses) {
        this.repository = repository;
        this.expenses = expenses;
    }

    public List<Comment> list(AuthUser user, String expenseId) {
        expenses.get(user, expenseId);
        return repository.findByExpense(expenseId);
    }

    public Comment add(CommentInput input) {
        String body = Text.plain(input.body());
        if (body.isEmpty()) {
            throw new BadRequestException("body is required");
        }
        return repository.save(new Comment(Ids.next("cmt"), input.tenantId(), input.expenseId(), input.authorId(), body,
                Instant.now()));
    }
}
`);
java("comment", "CommentController", web("get", "post", "pv", "body", "status", "http").concat(["com.ledger.expense.ExpenseService", "java.util.List"]), `
@RestController
@RequestMapping("/api/expenses/{expenseId}/comments")
public class CommentController {

    private final CommentService service;
    private final ExpenseService expenses;

    public CommentController(CommentService service, ExpenseService expenses) {
        this.service = service;
        this.expenses = expenses;
    }

    @GetMapping
    public List<Comment> list(@AuthenticationPrincipal AuthUser user, @PathVariable String expenseId) {
        return service.list(user, expenseId);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Comment add(@AuthenticationPrincipal AuthUser user, @PathVariable String expenseId, @RequestBody CommentInput input) {
        expenses.get(user, expenseId);
        return service.add(input.forExpense(user.tenantId(), expenseId));
    }
}
`);
java("comment", "IntegrationCommentController", [
  "org.springframework.http.HttpStatus", "org.springframework.web.bind.annotation.PostMapping",
  "org.springframework.web.bind.annotation.RequestBody", "org.springframework.web.bind.annotation.RequestMapping",
  "org.springframework.web.bind.annotation.ResponseStatus", "org.springframework.web.bind.annotation.RestController",
], `
/**
 * Receives comments relayed from the mail and chat integrations. Restricted to the service role by the URL rules.
 */
@RestController
@RequestMapping("/api/integrations/comments")
public class IntegrationCommentController {

    private final CommentService service;

    public IntegrationCommentController(CommentService service) {
        this.service = service;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Comment relay(@RequestBody CommentInput input) {
        return service.add(input);
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------------------------------------------
java("export", "ExportRequest", [], `
public record ExportRequest(String name) {
}
`);
java("export", "ExportJob", [], `
public record ExportJob(String id, String tenantId, String ownerId, String name, String path, int rows) {
}
`);
java("export", "ExportRepository", COLL, `
@Repository
public class ExportRepository {

    private final Map<String, ExportJob> store = new ConcurrentHashMap<>();

    public ExportJob save(ExportJob job) {
        store.put(job.id(), job);
        return job;
    }

    public Optional<ExportJob> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<ExportJob> findByOwner(String tenantId, String ownerId) {
        return store.values().stream()
                .filter(j -> j.tenantId().equals(tenantId) && j.ownerId().equals(ownerId))
                .sorted(Comparator.comparing(ExportJob::id))
                .toList();
    }
}
`);
java("export", "ExportService", [
  "com.ledger.common.Access", "com.ledger.common.BadRequestException", "com.ledger.common.Ids",
  "com.ledger.common.NotFoundException", "com.ledger.common.Text", "com.ledger.config.LedgerProperties",
  "com.ledger.expense.Expense", "com.ledger.expense.ExpenseRepository", "com.ledger.security.AuthUser",
  "java.io.IOException", "java.io.UncheckedIOException", "java.nio.file.Files", "java.nio.file.Path",
  "java.util.List", "org.springframework.stereotype.Service",
], `
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
        StringBuilder csv = new StringBuilder("id,description,amountCents,currency\\n");
        for (Expense e : rows) {
            csv.append(e.id()).append(',')
                    .append('"').append(e.description().replace("\\"", "'")).append('"').append(',')
                    .append(e.amountCents()).append(',')
                    .append(e.currency()).append('\\n');
        }
        return csv.toString();
    }
}
`);
java("export", "ExportController", web("get", "post", "pv", "body", "status", "http").concat([
  "java.util.List", "org.springframework.http.HttpHeaders", "org.springframework.http.MediaType", "org.springframework.http.ResponseEntity",
]), `
@RestController
@RequestMapping("/api/exports")
public class ExportController {

    private final ExportService service;

    public ExportController(ExportService service) {
        this.service = service;
    }

    @GetMapping
    public List<ExportJob> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ExportJob create(@AuthenticationPrincipal AuthUser user, @RequestBody ExportRequest request) {
        return service.create(user, request);
    }

    @GetMapping("/{id}")
    public ExportJob get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.get(user, id);
    }

    @GetMapping("/{id}/download")
    public ResponseEntity<byte[]> download(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        ExportJob job = service.get(user, id);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/csv"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\\"" + service.downloadName(job) + "\\"")
                .body(service.read(user, id));
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Billing
// ---------------------------------------------------------------------------------------------------------------
java("billing", "Subscription", ["java.time.LocalDate"], `
public record Subscription(String tenantId, String plan, int seats, LocalDate renewsOn) {
}
`);
java("billing", "Invoice", ["java.time.LocalDate"], `
public record Invoice(String id, String tenantId, String number, long amountCents, String status, LocalDate issuedOn) {
}
`);
java("billing", "BillingRepository", COLL, `
@Repository
public class BillingRepository {

    private final Map<String, Subscription> subscriptions = new ConcurrentHashMap<>();
    private final Map<String, Invoice> invoices = new ConcurrentHashMap<>();

    public Subscription save(Subscription subscription) {
        subscriptions.put(subscription.tenantId(), subscription);
        return subscription;
    }

    public Invoice save(Invoice invoice) {
        invoices.put(invoice.id(), invoice);
        return invoice;
    }

    public Optional<Subscription> subscriptionOf(String tenantId) {
        return Optional.ofNullable(subscriptions.get(tenantId));
    }

    public List<Invoice> invoicesOf(String tenantId) {
        return invoices.values().stream()
                .filter(i -> i.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Invoice::number))
                .toList();
    }
}
`);
java("billing", "BillingService", ["com.ledger.common.NotFoundException", "java.util.List", "org.springframework.stereotype.Service"], `
@Service
public class BillingService {

    private final BillingRepository repository;

    public BillingService(BillingRepository repository) {
        this.repository = repository;
    }

    public Subscription plan(String tenantId) {
        return repository.subscriptionOf(tenantId).orElseThrow(() -> new NotFoundException("subscription"));
    }

    public List<Invoice> invoices(String tenantId) {
        return repository.invoicesOf(tenantId);
    }
}
`);
java("billing", "BillingController", [
  "java.util.List", "org.springframework.web.bind.annotation.GetMapping", "org.springframework.web.bind.annotation.RequestHeader",
  "org.springframework.web.bind.annotation.RequestMapping", "org.springframework.web.bind.annotation.RestController",
], `
@RestController
@RequestMapping("/api/billing")
public class BillingController {

    private final BillingService service;

    public BillingController(BillingService service) {
        this.service = service;
    }

    @GetMapping("/plan")
    public Subscription plan(@RequestHeader("X-Tenant-Id") String tenantId) {
        return service.plan(tenantId);
    }

    @GetMapping("/invoices")
    public List<Invoice> invoices(@RequestHeader("X-Tenant-Id") String tenantId) {
        return service.invoices(tenantId);
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------------------------------------------
java("search", "SearchHit", [], `
public record SearchHit(String type, String id, String title) {
}
`);
java("search", "GlobalSearchService", [
  "com.ledger.comment.CommentRepository", "com.ledger.common.BadRequestException", "com.ledger.expense.ExpenseRepository",
  "com.ledger.security.AuthUser", "com.ledger.vendor.VendorRepository", "java.util.ArrayList", "java.util.List",
  "org.springframework.stereotype.Service",
], `
@Service
public class GlobalSearchService {

    private final ExpenseRepository expenses;
    private final VendorRepository vendors;
    private final CommentRepository comments;

    public GlobalSearchService(ExpenseRepository expenses, VendorRepository vendors, CommentRepository comments) {
        this.expenses = expenses;
        this.vendors = vendors;
        this.comments = comments;
    }

    public List<SearchHit> search(AuthUser user, String query) {
        if (query == null || query.strip().length() < 3) {
            throw new BadRequestException("query is too short");
        }
        String q = query.strip();
        List<SearchHit> hits = new ArrayList<>();
        expenses.searchByTenant(user.tenantId(), q).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .forEach(e -> hits.add(new SearchHit("expense", e.id(), e.description())));
        if (user.isManager()) {
            vendors.search(user.tenantId(), q).forEach(v -> hits.add(new SearchHit("vendor", v.id(), v.name())));
        }
        comments.search(q).forEach(c -> hits.add(new SearchHit("comment", c.id(), c.body())));
        return hits;
    }
}
`);
java("search", "SearchController", [
  "com.ledger.security.AuthUser", "java.util.List", "org.springframework.security.core.annotation.AuthenticationPrincipal",
  "org.springframework.web.bind.annotation.GetMapping", "org.springframework.web.bind.annotation.RequestMapping",
  "org.springframework.web.bind.annotation.RequestParam", "org.springframework.web.bind.annotation.RestController",
], `
@RestController
@RequestMapping("/api/search")
public class SearchController {

    private final GlobalSearchService service;

    public SearchController(GlobalSearchService service) {
        this.service = service;
    }

    @GetMapping
    public List<SearchHit> search(@AuthenticationPrincipal AuthUser user, @RequestParam("q") String query) {
        return service.search(user, query);
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------------------------------------------
java("admin", "RoleChange", ["com.ledger.security.Role"], `
public record RoleChange(Role role) {
}
`);
java("admin", "TenantLimits", [], `
public record TenantLimits(int maxUsers, int maxExpensesPerMonth) {
}
`);
java("admin", "AdminService", [
  "com.ledger.common.Access", "com.ledger.common.NotFoundException", "com.ledger.expense.ExpenseRepository",
  "com.ledger.security.AuthUser", "com.ledger.security.Role", "com.ledger.tenant.Tenant", "com.ledger.tenant.TenantRepository",
  "com.ledger.user.User", "com.ledger.user.UserRepository", "java.util.List", "java.util.Map",
  "org.springframework.stereotype.Service",
], `
@Service
public class AdminService {

    private final UserRepository users;
    private final TenantRepository tenants;
    private final ExpenseRepository expenses;

    public AdminService(UserRepository users, TenantRepository tenants, ExpenseRepository expenses) {
        this.users = users;
        this.tenants = tenants;
        this.expenses = expenses;
    }

    public List<User> listUsers(AuthUser actor) {
        return users.findByTenant(actor.tenantId());
    }

    public User changeRole(AuthUser actor, String userId, Role role) {
        User target = users.findById(userId).orElseThrow(() -> new NotFoundException("user"));
        Access.requireTenant(actor, target.tenantId());
        return users.save(target.withRole(role));
    }

    public User deactivate(AuthUser actor, String userId) {
        User target = users.findById(userId).orElseThrow(() -> new NotFoundException("user"));
        Access.requireTenant(actor, target.tenantId());
        return users.save(target.withActive(false));
    }

    public List<Tenant> listTenants(AuthUser actor) {
        return tenants.findById(actor.tenantId()).map(List::of).orElse(List.of());
    }

    public Tenant updateLimits(AuthUser actor, String tenantId, TenantLimits limits) {
        Access.requireTenant(actor, tenantId);
        Tenant tenant = tenants.findById(tenantId).orElseThrow(() -> new NotFoundException("tenant"));
        return tenants.save(tenant.withLimits(limits.maxUsers(), limits.maxExpensesPerMonth()));
    }

    public Map<String, Integer> stats(AuthUser actor) {
        return Map.of("users", users.findByTenant(actor.tenantId()).size(),
                "expenses", expenses.findByTenant(actor.tenantId()).size());
    }
}
`);
java("admin", "AdminUserController", web("get", "post", "put", "pv", "body").concat(["com.ledger.user.User", "java.util.List"]), `
@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {

    private final AdminService service;

    public AdminUserController(AdminService service) {
        this.service = service;
    }

    @GetMapping
    public List<User> list(@AuthenticationPrincipal AuthUser user) {
        return service.listUsers(user);
    }

    @PutMapping("/{id}/roles")
    public User changeRole(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody RoleChange change) {
        return service.changeRole(user, id, change.role());
    }

    @PostMapping("/{id}/deactivate")
    public User deactivate(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.deactivate(user, id);
    }
}
`);
java("admin", "AdminTenantController", web("get", "put", "pv", "body").concat(["com.ledger.tenant.Tenant", "java.util.List"]), `
@RestController
@RequestMapping("/api/admin/tenants")
public class AdminTenantController {

    private final AdminService service;

    public AdminTenantController(AdminService service) {
        this.service = service;
    }

    @GetMapping
    public List<Tenant> list(@AuthenticationPrincipal AuthUser user) {
        return service.listTenants(user);
    }

    @PutMapping("/{id}/limits")
    public Tenant updateLimits(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody TenantLimits limits) {
        return service.updateLimits(user, id, limits);
    }
}
`);
java("admin", "AdminStatsController", web("get").concat(["java.util.Map"]), `
@RestController
@RequestMapping("/api/admin/stats")
public class AdminStatsController {

    private final AdminService service;

    public AdminStatsController(AdminService service) {
        this.service = service;
    }

    @GetMapping
    public Map<String, Integer> stats(@AuthenticationPrincipal AuthUser user) {
        return service.stats(user);
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Smaller modules. Each is authorized in one of several styles:
//   A  service lookup that checks tenant and owner-or-manager (private records)
//   B  repository methods that always take the tenant id, owner-or-manager check in the service (private records)
//   C  tenant-wide reads, the controller checks owner-or-manager on writes
//   D  tenant-wide reads, writes limited to managers by method security
//   E  manager-only module (class level method security), tenant scoped service
//   F  strictly personal records (owner only)
// ---------------------------------------------------------------------------------------------------------------
const f = (name, type, a, b = a, raw = false) => ({ name, type, a, b, raw });
const lit = (type, v) => (type === "String" ? JSON.stringify(v) : type === "long" ? `${v}L` : type === "LocalDate" ? `LocalDate.parse("${v}")` : String(v));
const wrap = (items, indent) => {
  const out = [];
  for (let i = 0; i < items.length; i += 3) out.push(items.slice(i, i + 3).join(", "));
  return out.join(`,\n${" ".repeat(indent)}`);
};

const MODULES = [
  { key: "categories", entity: "Category", prefix: "cat", style: "A", fields: [f("name", "String", "Travel", "Meals"), f("color", "String", "blue", "green"), f("archived", "boolean", false)],
    extra: { serviceCode: `
    public List<CategoryDto> archived(AuthUser user) {
        return list(user).stream().filter(CategoryDto::archived).toList();
    }`, controllerCode: `
    @GetMapping("/archived")
    public List<CategoryDto> archived(@AuthenticationPrincipal AuthUser user) {
        return service.archived(user);
    }`, routes: [{ method: "GET", path: "/archived", kind: "list" }] } },
  { key: "tags", entity: "Tag", prefix: "tag", style: "C", fields: [f("label", "String", "reimbursable", "client-billable"), f("color", "String", "orange", "teal")],
    extra: { repoImports: ["java.util.Set"], repoCode: `
    private final Map<String, Set<String>> attachments = new ConcurrentHashMap<>();

    public void attach(String tagId, String expenseId) {
        attachments.computeIfAbsent(tagId, k -> ConcurrentHashMap.newKeySet()).add(expenseId);
    }

    public Set<String> attachedTo(String tagId) {
        return attachments.getOrDefault(tagId, Set.of());
    }`, serviceDeps: [["ExpenseService", "expenses", "com.ledger.expense.ExpenseService"]], serviceCode: `
    public int attach(AuthUser user, Tag tag, String expenseId) {
        expenses.get(user, expenseId);
        repository.attach(tag.id(), expenseId);
        return repository.attachedTo(tag.id()).size();
    }`, controllerImports: ["com.ledger.common.Access", "java.util.Map"], controllerCode: `
    @PostMapping("/{id}/attach/{expenseId}")
    public Map<String, Integer> attach(@AuthenticationPrincipal AuthUser user, @PathVariable String id,
                                       @PathVariable String expenseId) {
        Tag tag = service.find(user, id);
        Access.requireOwnerOrManager(user, tag.ownerId());
        return Map.of("attached", service.attach(user, tag, expenseId));
    }`, routes: [{ method: "POST", path: "/{id}/attach/ex-a1", rw: "w" }] } },
  { key: "notes", entity: "Note", prefix: "note", style: "A", fields: [f("body", "String", "Call the supplier about the invoice", "Check the parking receipt"), f("linkedExpenseId", "String", "ex-a1", "ex-b1", true)],
    extra: { serviceDeps: [["ExpenseService", "expenses", "com.ledger.expense.ExpenseService"]], guard: `
        if (dto.linkedExpenseId() != null) {
            expenses.get(user, dto.linkedExpenseId());
        }` } },
  { key: "reminders", entity: "Reminder", prefix: "rem", style: "B", fields: [f("title", "String", "Submit March expenses", "Renew parking pass"), f("dueOn", "LocalDate", "2025-04-02", "2025-04-05"), f("done", "boolean", false)],
    extra: { serviceImports: ["com.ledger.common.BadRequestException", "java.time.LocalDate"], serviceCode: `
    public ReminderDto snooze(AuthUser user, String id, int days) {
        Reminder current = owned(user, id);
        if (days < 1 || days > 30) {
            throw new BadRequestException("days must be between 1 and 30");
        }
        LocalDate base = current.dueOn() == null ? LocalDate.now() : current.dueOn();
        Reminder next = new Reminder(current.id(), current.tenantId(), current.ownerId(), current.title(), base.plusDays(days), false);
        return ReminderMapper.toDto(repository.save(next));
    }`, controllerImports: ["org.springframework.web.bind.annotation.RequestParam"], controllerCode: `
    @PostMapping("/{id}/snooze")
    public ReminderDto snooze(@AuthenticationPrincipal AuthUser user, @PathVariable String id,
                              @RequestParam(defaultValue = "1") int days) {
        return service.snooze(user, id, days);
    }`, routes: [{ method: "POST", path: "/{id}/snooze", rw: "w" }] } },
  { key: "saved-filters", entity: "SavedFilter", prefix: "flt", style: "B", fields: [f("name", "String", "Large expenses", "Fuel"), f("query", "String", "hotel", "fuel")],
    extra: { serviceDeps: [["ExpenseRepository", "expenses", "com.ledger.expense.ExpenseRepository"], ["ExpenseMapper", "expenseMapper", "com.ledger.expense.ExpenseMapper"]], serviceImports: ["com.ledger.expense.ExpenseDto"], serviceCode: `
    public List<ExpenseDto> apply(AuthUser user, String id) {
        SavedFilter filter = owned(user, id);
        return expenses.searchByTenant(user.tenantId(), filter.query()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .map(expenseMapper::toDto)
                .toList();
    }`, controllerImports: ["com.ledger.expense.ExpenseDto"], controllerCode: `
    @GetMapping("/{id}/apply")
    public List<ExpenseDto> apply(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.apply(user, id);
    }`, routes: [{ method: "GET", path: "/{id}/apply", rw: "r" }] } },
  { key: "currencies", entity: "Currency", prefix: "cur", style: "D", fields: [f("code", "String", "EUR", "USD"), f("symbol", "String", "EUR", "USD"), f("rateMicros", "long", 1000000, 920000)],
    extra: { serviceCode: `
    public long convert(AuthUser user, String from, String to, long amountCents) {
        Currency source = byCode(user, from);
        Currency target = byCode(user, to);
        return amountCents * source.rateMicros() / target.rateMicros();
    }

    private Currency byCode(AuthUser user, String code) {
        return repository.listByTenant(user.tenantId()).stream()
                .filter(c -> c.code().equalsIgnoreCase(code))
                .findFirst()
                .orElseThrow(() -> new NotFoundException("currency"));
    }`, controllerImports: ["java.util.Map", "org.springframework.web.bind.annotation.RequestParam"], controllerCode: `
    @GetMapping("/convert")
    public Map<String, Long> convert(@AuthenticationPrincipal AuthUser user, @RequestParam String from,
                                     @RequestParam String to, @RequestParam long amount) {
        return Map.of("amountCents", service.convert(user, from, to, amount));
    }` } },
  { key: "tax-rates", entity: "TaxRate", prefix: "tax", style: "D", fields: [f("name", "String", "Standard", "Reduced"), f("percentBp", "int", 1900, 700), f("region", "String", "DE", "CH")],
    extra: { serviceCode: `
    public long apply(AuthUser user, String id, long amountCents) {
        TaxRate rate = scoped(user, id);
        return amountCents * rate.percentBp() / 10000;
    }`, controllerImports: ["java.util.Map", "org.springframework.web.bind.annotation.RequestParam"], controllerCode: `
    @GetMapping("/{id}/apply")
    public Map<String, Long> apply(@AuthenticationPrincipal AuthUser user, @PathVariable String id,
                                   @RequestParam long amountCents) {
        return Map.of("taxCents", service.apply(user, id, amountCents));
    }`, routes: [{ method: "GET", path: "/{id}/apply?amountCents=1000", rw: "r" }] } },
  { key: "contracts", entity: "Contract", prefix: "con", style: "E", fields: [f("title", "String", "Office lease", "Fleet maintenance"), f("counterparty", "String", "Harbor Properties", "Roadside Services"), f("startsOn", "LocalDate", "2024-01-01", "2024-06-01"), f("endsOn", "LocalDate", "2026-12-31", "2025-05-31"), f("valueCents", "long", 4800000, 960000)],
    extra: { serviceImports: ["java.time.LocalDate"], serviceCode: `
    public List<ContractDto> expiring(AuthUser user, int days) {
        LocalDate limit = LocalDate.now().plusDays(days);
        return list(user).stream().filter(c -> c.endsOn() != null && !c.endsOn().isAfter(limit)).toList();
    }`, controllerImports: ["org.springframework.web.bind.annotation.RequestParam"], controllerCode: `
    @GetMapping("/expiring")
    public List<ContractDto> expiring(@AuthenticationPrincipal AuthUser user, @RequestParam(defaultValue = "90") int days) {
        return service.expiring(user, days);
    }`, routes: [{ method: "GET", path: "/expiring", kind: "list" }] } },
  { key: "departments", entity: "Department", prefix: "dep", style: "D", fields: [f("name", "String", "Operations", "Field Sales"), f("code", "String", "OPS", "FSL"), f("headcount", "int", 42, 17)] },
  { key: "locations", entity: "Location", prefix: "loc", style: "D", fields: [f("name", "String", "Head office", "Depot"), f("city", "String", "Hamburg", "Basel"), f("country", "String", "DE", "CH")] },
  { key: "assets", entity: "Asset", prefix: "ast", style: "C", fields: [f("label", "String", "Laptop 14 inch", "Handheld scanner"), f("serialNumber", "String", "LT-88231", "HS-1190"), f("purchasedOn", "LocalDate", "2024-09-12", "2024-11-03"), f("valueCents", "long", 129900, 45000)] },
  { key: "cards", entity: "Card", prefix: "crd", style: "A", fields: [f("nickname", "String", "Travel card", "Fuel card"), f("last4", "String", "4417", "9032"), f("limitCents", "long", 500000, 150000), f("frozen", "boolean", false)],
    extra: { serviceCode: `
    public CardDto freeze(AuthUser user, String id) {
        Card current = require(user, id);
        Card next = new Card(current.id(), current.tenantId(), current.ownerId(), current.nickname(), current.last4(),
                current.limitCents(), true);
        return mapper.toDto(repository.save(next));
    }`, controllerCode: `
    @PostMapping("/{id}/freeze")
    public CardDto freeze(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.freeze(user, id);
    }`, routes: [{ method: "POST", path: "/{id}/freeze", rw: "w" }] } },
  { key: "mileage", entity: "MileageEntry", prefix: "mil", style: "A", fields: [f("purpose", "String", "Client visit", "Depot run"), f("tripDate", "LocalDate", "2025-03-14", "2025-03-18"), f("distanceKm", "int", 86, 40)],
    extra: { serviceImports: ["java.util.Map"], serviceCode: `
    public Map<String, Integer> summary(AuthUser user) {
        int total = repository.findByTenant(user.tenantId()).stream()
                .filter(e -> e.ownerId().equals(user.id()))
                .mapToInt(MileageEntry::distanceKm)
                .sum();
        return Map.of("totalKm", total);
    }`, controllerImports: ["java.util.Map"], controllerCode: `
    @GetMapping("/summary")
    public Map<String, Integer> summary(@AuthenticationPrincipal AuthUser user) {
        return service.summary(user);
    }` } },
  { key: "per-diems", entity: "PerDiem", prefix: "pdm", style: "C", fields: [f("destination", "String", "Vienna", "Zurich"), f("days", "int", 3, 2), f("rateCents", "long", 6800, 7400)] },
  { key: "reports", entity: "Report", prefix: "rpt", style: "A", fields: [f("title", "String", "Quarterly spend", "Fuel by month"), f("kind", "String", "spend", "fuel"), f("parameters", "String", "quarter=2025Q1", "range=12m")],
    extra: { serviceDeps: [["ExpenseRepository", "expenses", "com.ledger.expense.ExpenseRepository"]], serviceImports: ["java.util.Map"], serviceCode: `
    public Map<String, Integer> run(AuthUser user, String id) {
        require(user, id);
        long rows = expenses.findByTenant(user.tenantId()).stream()
                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))
                .count();
        return Map.of("rows", (int) rows);
    }`, controllerImports: ["java.util.Map"], controllerCode: `
    @PostMapping("/{id}/run")
    public Map<String, Integer> run(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.run(user, id);
    }`, routes: [{ method: "POST", path: "/{id}/run", rw: "w" }] } },
  { key: "notifications", entity: "Notification", prefix: "ntf", style: "F", fields: [f("subject", "String", "Expense approved", "Receipt missing"), f("body", "String", "Your expense was approved.", "Please attach a receipt."), f("read", "boolean", false)],
    extra: { serviceCode: `
    public NotificationDto markRead(AuthUser user, String id) {
        Notification current = requireOwn(user, id);
        Notification next = new Notification(current.id(), current.tenantId(), current.ownerId(), current.subject(), current.body(), true);
        return NotificationMapper.toDto(repository.save(next));
    }`, controllerCode: `
    @PostMapping("/{id}/read")
    public NotificationDto markRead(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.markRead(user, id);
    }`, routes: [{ method: "POST", path: "/{id}/read", rw: "w" }] } },
  { key: "preferences", entity: "Preference", prefix: "prf", style: "F", fields: [f("locale", "String", "de-DE", "fr-CH"), f("timezone", "String", "Europe/Berlin", "Europe/Zurich"), f("digest", "boolean", true, false)],
    extra: { serviceCode: `
    public PreferenceDto mine(AuthUser user) {
        return repository.findByTenant(user.tenantId()).stream()
                .filter(p -> p.ownerId().equals(user.id()))
                .findFirst()
                .map(PreferenceMapper::toDto)
                .orElseThrow(() -> new NotFoundException("preference"));
    }`, controllerCode: `
    @GetMapping("/mine")
    public PreferenceDto mine(@AuthenticationPrincipal AuthUser user) {
        return service.mine(user);
    }` } },
  { key: "api-keys", entity: "ApiKey", prefix: "key", style: "F", fields: [f("label", "String", "Expense sync", "Mobile app"), f("prefix", "String", "lk_3f9a", "lk_77c1"), f("scope", "String", "expenses:read", "expenses:write")],
    extra: { serviceImports: ["com.ledger.common.Ids"], serviceCode: `
    public ApiKeyDto rotate(AuthUser user, String id) {
        ApiKey current = requireOwn(user, id);
        String fresh = "lk_" + Ids.next("k").substring(2);
        ApiKey next = new ApiKey(current.id(), current.tenantId(), current.ownerId(), current.label(), fresh, current.scope());
        return ApiKeyMapper.toDto(repository.save(next));
    }`, controllerCode: `
    @PostMapping("/{id}/rotate")
    public ApiKeyDto rotate(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.rotate(user, id);
    }`, routes: [{ method: "POST", path: "/{id}/rotate", rw: "w" }] } },
  { key: "audit-entries", entity: "AuditEntry", prefix: "aud", style: "E", readOnly: true, fields: [f("action", "String", "expense.submitted", "vendor.created"), f("subject", "String", "ex-a1", "ven-b1"), f("detail", "String", "submitted for approval", "created by manager")] },
  { key: "templates", entity: "Template", prefix: "tpl", style: "D", fields: [f("name", "String", "Monthly summary", "Fuel report"), f("kind", "String", "report", "report"), f("body", "String", "Total: {{total}}", "Fuel: {{fuel}}")],
    extra: { serviceDeps: [["LedgerProperties", "properties", "com.ledger.config.LedgerProperties"]], serviceImports: ["com.ledger.common.Text", "java.io.IOException", "java.io.UncheckedIOException", "java.nio.file.Files", "java.nio.file.Path"], serviceCode: `
    public String publish(AuthUser user, String id) {
        Template current = scoped(user, id);
        Path dir = properties.templatePath().resolve(user.tenantId());
        Path target = dir.resolve(Text.safeSegment(current.name()) + ".tpl");
        try {
            Files.createDirectories(dir);
            Files.writeString(target, current.body() == null ? "" : current.body());
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return target.getFileName().toString();
    }`, controllerImports: ["java.util.Map"], controllerCode: `
    @PostMapping("/{id}/publish")
    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    public Map<String, String> publish(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return Map.of("file", service.publish(user, id));
    }`, routes: [{ method: "POST", path: "/{id}/publish", rw: "w" }] } },
  { key: "policies", entity: "Policy", prefix: "pol", style: "E", fields: [f("name", "String", "Meal limit", "Lodging limit"), f("ruleKind", "String", "per-day", "per-night"), f("limitCents", "long", 7500, 15000), f("active", "boolean", true)] },
  { key: "webhooks", entity: "Webhook", prefix: "whk", style: "E", fields: [f("url", "String", "https://hooks.example.test/expenses", "https://hooks.example.test/fuel"), f("event", "String", "expense.approved", "expense.submitted"), f("active", "boolean", true)],
    extra: { serviceImports: ["java.util.Map"], serviceCode: `
    public Map<String, Object> ping(AuthUser user, String id) {
        Webhook hook = scoped(user, id);
        return Map.of("event", hook.event(), "active", hook.active());
    }`, controllerImports: ["java.util.Map"], controllerCode: `
    @PostMapping("/{id}/ping")
    public Map<String, Object> ping(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.ping(user, id);
    }`, routes: [{ method: "POST", path: "/{id}/ping", rw: "w" }] } },
  { key: "budgets", entity: "Budget", prefix: "bud", style: "B", fields: [f("name", "String", "Q2 travel", "Q2 fuel"), f("periodStart", "LocalDate", "2025-04-01", "2025-04-01"), f("limitCents", "long", 2500000, 800000), f("spentCents", "long", 640000, 210000)],
    extra: { serviceImports: ["java.util.Map"], serviceCode: `
    public Map<String, Long> remaining(AuthUser user, String id) {
        Budget budget = owned(user, id);
        return Map.of("remainingCents", budget.limitCents() - budget.spentCents());
    }`, controllerImports: ["java.util.Map"], controllerCode: `
    @GetMapping("/{id}/remaining")
    public Map<String, Long> remaining(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.remaining(user, id);
    }`, routes: [{ method: "GET", path: "/{id}/remaining", rw: "r" }] } },
  { key: "cost-centers", entity: "CostCenter", prefix: "cc", style: "D", fields: [f("code", "String", "CC-100", "CC-200"), f("name", "String", "Sales travel", "Depot costs"), f("parentCode", "String", "CC-000", "CC-000", true)] },
  { key: "purchase-orders", entity: "PurchaseOrder", prefix: "po", style: "A", fields: [f("number", "String", "PO-2025-0041", "PO-2025-0007"), f("vendorRef", "String", "ven-a1", "ven-b1", true), f("totalCents", "long", 182000, 64000), f("status", "String", "OPEN", "OPEN", true)],
    extra: { serviceDeps: [["VendorRepository", "vendors", "com.ledger.vendor.VendorRepository"]], serviceImports: ["com.ledger.common.ConflictException"], guard: `
        if (dto.vendorRef() != null) {
            vendors.findInTenant(user.tenantId(), dto.vendorRef()).orElseThrow(() -> new NotFoundException("vendor"));
        }`, serviceCode: `
    public PurchaseOrderDto receive(AuthUser user, String id) {
        PurchaseOrder current = require(user, id);
        if (!"OPEN".equals(current.status())) {
            throw new ConflictException("order is not open");
        }
        PurchaseOrder next = new PurchaseOrder(current.id(), current.tenantId(), current.ownerId(), current.number(),
                current.vendorRef(), current.totalCents(), "RECEIVED");
        return mapper.toDto(repository.save(next));
    }`, controllerCode: `
    @PostMapping("/{id}/receive")
    public PurchaseOrderDto receive(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.receive(user, id);
    }`, routes: [{ method: "POST", path: "/{id}/receive", rw: "w" }] } },
];
for (const m of MODULES) {
  m.pkg = m.key.replaceAll("-", "");
  m.base = `/api/${m.key}`;
  m.firstString = m.fields.find((x) => x.type === "String" && !x.raw)?.name;
}

function genModule(m) {
  const E = m.entity;
  const D = `${E}Dto`;
  const R = `${E}Repository`;
  const M = `${E}Mapper`;
  const S = `${E}Service`;
  const C = `${E}Controller`;
  const x = m.extra ?? {};
  const inst = m.style === "A" || m.style === "C";
  const tenantRepo = m.style === "B" || m.style === "D" || m.style === "E";
  const date = m.fields.some((q) => q.type === "LocalDate") ? ["java.time.LocalDate"] : [];
  const mp = inst ? "mapper" : M;
  const toDto = (e) => `${mp}.toDto(${e})`;
  const mapRef = inst ? "mapper::toDto" : `${M}::toDto`;

  java(m.pkg, E, date, `public record ${E}(String id, String tenantId, String ownerId,\n        ${wrap(m.fields.map((q) => `${q.type} ${q.name}`), 8)}) {\n}`);
  java(m.pkg, D, date, `public record ${D}(String id,\n        ${wrap(m.fields.map((q) => `${q.type} ${q.name}`), 8)}) {\n}`);

  // Mapper
  const val = (q) => (q.type !== "String" || q.raw ? `dto.${q.name}()` : q.name === m.firstString ? `Text.required(dto.${q.name}(), "${q.name}")` : `Text.plain(dto.${q.name}())`);
  const keep = (q) => `current.${q.name}()`;
  const toArgs = m.fields.map((q) => `e.${q.name}()`);
  const mapperBody = `
    ${inst ? "public" : "public static"} ${D} toDto(${E} e) {
        return new ${D}(e.id(),
                ${wrap(toArgs, 16)});
    }

    ${inst ? "public" : "public static"} ${E} create(AuthUser user, ${D} dto) {
        return new ${E}(Ids.next("${m.prefix}"), user.tenantId(), user.id(),
                ${wrap(m.fields.map(val), 16)});
    }

    ${inst ? "public" : "public static"} ${E} apply(${E} current, ${D} dto) {
        return new ${E}(current.id(), current.tenantId(), current.ownerId(),
                ${wrap(m.fields.map(val), 16)});
    }`;
  const mapperImports = ["com.ledger.common.Ids", "com.ledger.common.Text", "com.ledger.security.AuthUser"];
  if (inst) java(m.pkg, M, [...mapperImports, "org.springframework.stereotype.Component"], `@Component\npublic class ${M} {\n${mapperBody}\n}`);
  else java(m.pkg, M, mapperImports, `public final class ${M} {\n\n    private ${M}() {\n    }\n${mapperBody}\n}`);

  // Repository
  const repoCore = tenantRepo
    ? `
    private final Map<String, ${E}> store = new ConcurrentHashMap<>();

    public ${E} save(${E} entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<${E}> findByTenantAndId(String tenantId, String id) {
        return Optional.ofNullable(store.get(id)).filter(e -> e.tenantId().equals(tenantId));
    }

    public List<${E}> listByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(${E}::id))
                .toList();
    }

    public void removeInTenant(String tenantId, String id) {
        findByTenantAndId(tenantId, id).ifPresent(e -> store.remove(e.id()));
    }`
    : `
    private final Map<String, ${E}> store = new ConcurrentHashMap<>();

    public ${E} save(${E} entity) {
        store.put(entity.id(), entity);
        return entity;
    }

    public Optional<${E}> findById(String id) {
        return Optional.ofNullable(store.get(id));
    }

    public List<${E}> findByTenant(String tenantId) {
        return store.values().stream()
                .filter(e -> e.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(${E}::id))
                .toList();
    }

    public void delete(String id) {
        store.remove(id);
    }`;
  java(m.pkg, R, [...COLL, ...(x.repoImports ?? [])], `@Repository\npublic class ${R} {\n${repoCore}${x.repoCode ? `\n${x.repoCode}` : ""}\n}`);

  // Service
  const deps = [[R, "repository", null], ...(inst ? [[M, "mapper", null]] : []), ...(x.serviceDeps ?? [])];
  const fieldsDecl = deps.map(([t, n]) => `    private final ${t} ${n};`).join("\n");
  const ctor = `    public ${S}(${deps.map(([t, n]) => `${t} ${n}`).join(", ")}) {\n${deps.map(([, n]) => `        this.${n} = ${n};`).join("\n")}\n    }`;
  const listSrc = tenantRepo ? "repository.listByTenant(user.tenantId())" : "repository.findByTenant(user.tenantId())";
  const listFilter = m.style === "A" || m.style === "B" ? `\n                .filter(e -> user.isManager() || e.ownerId().equals(user.id()))` : m.style === "F" ? `\n                .filter(e -> e.ownerId().equals(user.id()))` : "";
  const listMethod = `
    public List<${D}> list(AuthUser user) {
        return ${listSrc}.stream()${listFilter}
                .map(${mapRef})
                .toList();
    }`;
  const validateCall = x.guard ? "\n        validate(user, dto);" : "";
  const validateDef = x.guard ? `\n\n    private void validate(AuthUser user, ${D} dto) {${x.guard}\n    }` : "";
  const lookupName = { A: "require", B: "owned", D: "scoped", E: "scoped", F: "requireOwn" }[m.style];
  const lookups = {
    A: `
    private ${E} require(AuthUser user, String id) {
        ${E} entity = repository.findById(id).orElseThrow(() -> new NotFoundException("${m.key}"));
        Access.requireTenant(user, entity.tenantId());
        Access.requireOwnerOrManager(user, entity.ownerId());
        return entity;
    }`,
    F: `
    private ${E} requireOwn(AuthUser user, String id) {
        ${E} entity = repository.findById(id).orElseThrow(() -> new NotFoundException("${m.key}"));
        Access.requireTenant(user, entity.tenantId());
        Access.requireOwner(user, entity.ownerId());
        return entity;
    }`,
    B: `
    private ${E} owned(AuthUser user, String id) {
        ${E} entity = repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("${m.key}"));
        Access.requireOwnerOrManager(user, entity.ownerId());
        return entity;
    }`,
    D: `
    private ${E} scoped(AuthUser user, String id) {
        return repository.findByTenantAndId(user.tenantId(), id).orElseThrow(() -> new NotFoundException("${m.key}"));
    }`,
  };
  lookups.E = lookups.D;
  let serviceBody;
  if (m.style === "C") {
    serviceBody = `
${fieldsDecl}

${ctor}
${listMethod}

    public ${E} find(AuthUser user, String id) {
        return repository.findById(id)
                .filter(e -> e.tenantId().equals(user.tenantId()))
                .orElseThrow(() -> new NotFoundException("${m.key}"));
    }

    public ${D} view(AuthUser user, String id) {
        return ${toDto("find(user, id)")};
    }

    public ${D} create(AuthUser user, ${D} dto) {
        return ${toDto(`repository.save(${mp}.create(user, dto))`)};
    }

    public ${D} update(${E} current, ${D} dto) {
        return ${toDto(`repository.save(${mp}.apply(current, dto))`)};
    }

    public void remove(${E} current) {
        repository.delete(current.id());
    }${x.serviceCode ?? ""}`;
  } else {
    const del = tenantRepo ? `repository.removeInTenant(user.tenantId(), current.id());` : `repository.delete(current.id());`;
    const writes = m.readOnly ? "" : `

    public ${D} create(AuthUser user, ${D} dto) {${validateCall}
        return ${toDto(`repository.save(${mp}.create(user, dto))`)};
    }

    public ${D} update(AuthUser user, String id, ${D} dto) {
        ${E} current = ${lookupName}(user, id);${validateCall}
        return ${toDto(`repository.save(${mp}.apply(current, dto))`)};
    }

    public void delete(AuthUser user, String id) {
        ${E} current = ${lookupName}(user, id);
        ${del}
    }`;
    serviceBody = `
${fieldsDecl}

${ctor}
${listMethod}

    public ${D} get(AuthUser user, String id) {
        return ${toDto(`${lookupName}(user, id)`)};
    }${writes}${x.serviceCode ?? ""}
${lookups[m.style]}${validateDef}`;
  }
  const serviceImports = ["com.ledger.common.Access", "com.ledger.common.NotFoundException", "com.ledger.security.AuthUser", "java.util.List", "org.springframework.stereotype.Service", ...date, ...(x.serviceImports ?? []), ...(x.serviceDeps ?? []).map((d) => d[2])];
  java(m.pkg, S, serviceImports, `@Service\npublic class ${S} {\n${serviceBody}\n}`);

  // Controller
  const needsMgr = m.style === "D";
  const pre = needsMgr ? `\n    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")` : "";
  const classPre = m.style === "E" ? `\n@PreAuthorize("@access.isManager()")` : "";
  const classDoc = { A: "", B: "", C: `/**\n * Everyone in the tenant can read these records; changes are limited to the owner or a manager.\n */\n`, D: `/**\n * Reads are open to the tenant; writes are limited to managers.\n */\n`, E: "", F: "" }[m.style];
  let ctl;
  if (m.style === "C") {
    ctl = `
    @GetMapping
    public List<${D}> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public ${D} get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.view(user, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ${D} create(@AuthenticationPrincipal AuthUser user, @RequestBody ${D} dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")
    public ${D} update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody ${D} dto) {
        ${E} current = service.find(user, id);
        Access.requireOwnerOrManager(user, current.ownerId());
        return service.update(current, dto);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        ${E} current = service.find(user, id);
        Access.requireOwnerOrManager(user, current.ownerId());
        service.remove(current);
    }`;
  } else {
    const writes = m.readOnly ? "" : `

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)${pre}
    public ${D} create(@AuthenticationPrincipal AuthUser user, @RequestBody ${D} dto) {
        return service.create(user, dto);
    }

    @PutMapping("/{id}")${pre}
    public ${D} update(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody ${D} dto) {
        return service.update(user, id, dto);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)${pre}
    public void delete(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        service.delete(user, id);
    }`;
    ctl = `
    @GetMapping
    public List<${D}> list(@AuthenticationPrincipal AuthUser user) {
        return service.list(user);
    }

    @GetMapping("/{id}")
    public ${D} get(@AuthenticationPrincipal AuthUser user, @PathVariable String id) {
        return service.get(user, id);
    }${writes}`;
  }
  const ctlImports = [...web("get", "post", "put", "del", "pv", "body", "status", "http", "pre"), "java.util.List", "com.ledger.common.Access", ...(x.controllerImports ?? [])];
  java(m.pkg, C, ctlImports, `${classDoc}@RestController\n@RequestMapping("${m.base}")${classPre}\npublic class ${C} {\n\n    private final ${S} service;\n\n    public ${C}(${S} service) {\n        this.service = service;\n    }\n${ctl}${x.controllerCode ? `\n${x.controllerCode}` : ""}\n}`);
}
MODULES.forEach(genModule);

// ---------------------------------------------------------------------------------------------------------------
// Demo data
// ---------------------------------------------------------------------------------------------------------------
const slugOf = { a: "alpha", b: "bravo" };
const moduleSeeds = [];
const loaderImports = [
  "com.ledger.billing.BillingRepository", "com.ledger.billing.Invoice", "com.ledger.billing.Subscription",
  "com.ledger.approval.Approval", "com.ledger.approval.ApprovalRepository", "com.ledger.comment.Comment",
  "com.ledger.comment.CommentRepository", "com.ledger.expense.Expense", "com.ledger.expense.ExpenseRepository",
  "com.ledger.project.Project", "com.ledger.project.ProjectRepository", "com.ledger.receipt.Receipt",
  "com.ledger.receipt.ReceiptRepository", "com.ledger.security.Role", "com.ledger.statement.Statement",
  "com.ledger.statement.StatementLine", "com.ledger.statement.StatementRepository", "com.ledger.tenant.Tenant",
  "com.ledger.tenant.TenantRepository", "com.ledger.user.User", "com.ledger.user.UserRepository",
  "com.ledger.vendor.BankDetails", "com.ledger.vendor.Vendor", "com.ledger.vendor.VendorRepository",
  "java.nio.charset.StandardCharsets", "java.time.Instant", "java.time.LocalDate", "java.util.List",
  "org.springframework.boot.ApplicationArguments", "org.springframework.boot.ApplicationRunner",
  "org.springframework.boot.autoconfigure.condition.ConditionalOnProperty", "org.springframework.context.ApplicationContext",
  "org.springframework.stereotype.Component",
];
for (const m of MODULES) {
  loaderImports.push(`com.ledger.${m.pkg}.${m.entity}`, `com.ledger.${m.pkg}.${m.entity}Repository`);
  for (const side of ["a", "b"]) {
    const slug = slugOf[side];
    const owner = m.style === "E" ? `u-${slug}-mgr` : `u-${slug}-user1`;
    const args = m.fields.map((q) => lit(q.type, side === "a" ? q.a : q.b));
    moduleSeeds.push(`        bean(${m.entity}Repository.class).save(new ${m.entity}("${m.prefix}-${side}1", "t-${slug}", "${owner}",\n                ${wrap(args, 16)}));`);
  }
}
java("bootstrap", "DemoDataLoader", loaderImports, `
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
${moduleSeeds.join("\n")}
    }
}
`);

// ---------------------------------------------------------------------------------------------------------------
// Build files and resources
// ---------------------------------------------------------------------------------------------------------------
put("pom.xml", `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.5.0</version>
        <relativePath/>
    </parent>

    <groupId>com.ledger</groupId>
    <artifactId>ledger</artifactId>
    <version>1.14.2</version>
    <name>ledger</name>
    <description>Expense and procurement service</description>

    <properties>
        <java.version>21</java.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
`);
put("src/main/resources/application.yml", `spring:
  application:
    name: ledger

server:
  port: 8080

ledger:
  token-secret: \${LEDGER_TOKEN_SECRET:}
  export-dir: \${LEDGER_EXPORT_DIR:data/exports}
  template-dir: \${LEDGER_TEMPLATE_DIR:data/templates}
  demo-data: \${LEDGER_DEMO_DATA:true}
`);

// ---------------------------------------------------------------------------------------------------------------
// Answer key (line numbers come from anchors in the generated text)
// ---------------------------------------------------------------------------------------------------------------
const textLines = (rel) => {
  if (!files.has(rel)) throw new Error(`no such file ${rel}`);
  return files.get(rel).split("\n");
};
function at(rel, anchor, from = 1) {
  const ls = textLines(rel);
  for (let i = from - 1; i < ls.length; i++) if (ls[i].includes(anchor)) return i + 1;
  throw new Error(`anchor not found in ${rel}: ${anchor}`);
}
function close(rel, from) {
  const ls = textLines(rel);
  for (let i = from - 1; i < ls.length; i++) if (ls[i] === "    }") return i + 1;
  throw new Error(`no method end after ${from} in ${rel}`);
}
function annoStart(rel, sigLine) {
  const ls = textLines(rel);
  let s = sigLine;
  while (s > 1 && /^ {4}@/.test(ls[s - 2])) s--;
  return s;
}
/** Range of one method (annotations through closing brace), or of several consecutive methods first..last. */
function meth(rel, sig, lastSig = sig) {
  const first = at(rel, sig);
  const last = lastSig === sig ? first : at(rel, lastSig, first);
  return { path: rel, startLine: annoStart(rel, first), endLine: close(rel, last) };
}
const span = (rel, startAnchor, endAnchor = startAnchor, endOffset = 0) => {
  const s = at(rel, startAnchor);
  return { path: rel, startLine: s, endLine: at(rel, endAnchor, s) + endOffset };
};
const P = (pkg, name) => jpath(pkg, name);
const mod = (key) => MODULES.find((m) => m.key === key);
const MP = (key, kind) => P(mod(key).pkg, `${mod(key).entity}${kind}`);

const items = [];
const decoys = [];
const item = (id, loc, category, description, alsoAt, mention) =>
  items.push({ id, path: loc.path, startLine: loc.startLine, endLine: loc.endLine, category, description, alsoAt, oracle: { mention, lineSlack: 3 } });
const decoy = (id, loc, category, description) =>
  decoys.push({ id, path: loc.path, startLine: loc.startLine, endLine: loc.endLine, category, description });

const VC = P("vendor", "VendorController");
const VS = P("vendor", "VendorService");
item("jl-vendor-bank", meth(VC, "public BankDetailsDto replaceBankDetails("), "authz",
  "PUT /api/tenants/{tenantId}/vendors/{id}/bank-details is the only one of the ten vendor endpoints without @PreAuthorize(\"@access.canManage(#tenantId)\"); VendorService trusts the path tenantId, so any authenticated user can replace another tenant's vendor bank account details.",
  [meth(VS, "public BankDetailsDto replaceBankDetails(")],
  ["bank[- ]?details?", "iban", "replace.{0,20}bank", "bank account", "canManage"]);

const RC = P("receipt", "ReceiptController");
const RS = P("receipt", "ReceiptService");
item("jl-receipt-download", meth(RC, "public ResponseEntity<byte[]> download("), "authz",
  "GET /api/receipts/{receiptId}/download loads the receipt through ReceiptService.load, which goes straight to the repository without the tenant and owner-or-manager check that ExpenseService.get applies on the other receipt routes, so any authenticated user can download any receipt by id.",
  [meth(RS, "public Receipt load(")],
  ["receipt", "download"]);

const PSC = P("statement", "PublicStatementController");
const SS = P("statement", "StatementService");
item("jl-statement-public", meth(PSC, "public StatementView shared("), "authz",
  "GET /public/statements/{id}?token= verifies the share token signature but never compares the token's subject with {id}, and StatementService.build does no authorization, so any valid share token opens any statement.",
  [meth(SS, "public StatementView build(")],
  ["statements?", "share (token|link)", "/public/", "token"]);

const AC = P("approval", "ApprovalController");
const AS = P("approval", "ApprovalService");
item("jl-bulk-approve", meth(AC, "public List<Approval> bulkApprove("), ["authz", "business-logic"],
  "POST /api/approvals/bulk-approve takes approverId from the request body and uses it for the maker-checker rule and the audit entry, so a requester can name another manager and approve their own request; the single approve route correctly uses the authenticated principal.",
  [meth(AS, "public List<Approval> approveAll("), meth(AS, "private Approval decide(")],
  ["bulk", "approver ?id", "approve ?all", "maker.?checker", "self.?approv", "own request"]);

const ES = P("export", "ExportService");
const EXC = P("export", "ExportController");
const TXT = P("common", "Text");
item("jl-export-name", span(ES, 'Path target = exportDir.resolve(name + ".csv");', "throw new UncheckedIOException(ex);", 1), "path-traversal",
  "ExportService.create builds the export file path with exportDir.resolve(Text.plain(name) + \".csv\"). Text.plain only strips markup for HTML output, so ../ sequences in the export name survive and the CSV is written outside the export directory.",
  [span(ES, "String name = Text.plain(request.name());"), meth(TXT, "public static String plain("), meth(EXC, "public ExportJob create(")],
  ["export", "file ?name", "travers", "plain\\(", "\\.csv", "resolve"]);

const AUC = P("admin", "AdminUserController");
const ATC = P("admin", "AdminTenantController");
const ASC = P("admin", "AdminStatsController");
const ASV = P("admin", "AdminService");
const SEC = P("security", "SecurityConfig");
item("jl-admin-nested", meth(AUC, "public User changeRole("), "authz",
  "The URL rule requestMatchers(\"/api/admin/*\").hasRole(\"ADMIN\") matches one path segment only, so nested admin routes such as /api/admin/users/{id}/roles and /api/admin/tenants/{id}/limits fall through to anyRequest().authenticated(); the admin controllers have no inline role check, so any authenticated user can change roles and tenant limits.",
  [meth(AUC, "public User deactivate("), meth(ATC, "public Tenant updateLimits("), span(SEC, '.requestMatchers("/api/admin/*").hasRole("ADMIN")'), meth(ASV, "public User changeRole(")],
  ["admin.{0,50}(role|tenant|limit|deactivat|nested|path|route|endpoint)", "requestMatchers", "/api/admin/\\*", "(roles?|limits?).{0,40}admin"]);

const GSS = P("search", "GlobalSearchService");
item("jl-search-comments", span(GSS, "comments.search(q).forEach("), "authz",
  "GlobalSearchService scopes the expense and vendor searches by tenant but the comment search (CommentRepository.search) has no tenant filter, so GET /api/search?q= returns other tenants' comments.",
  [meth(P("comment", "CommentRepository"), "public List<Comment> search("), meth(P("search", "SearchController"), "public List<SearchHit> search(")],
  ["global ?search", "comments?.{0,80}(search|tenant)", "(search|quer(y|ies)).{0,80}comments?"]);

const PS = P("project", "ProjectService");
const PCT = P("project", "ProjectController");
item("jl-project-transfer", meth(PS, "public int transferExpenses("), "authz",
  "transferExpenses checks that the caller manages the source project but loads the target project by id without checking it belongs to the caller's tenant, so a manager can move expenses into another tenant's project.",
  [meth(PCT, "public Map<String, Integer> transferExpenses("), meth(P("expense", "ExpenseRepository"), "public int reassign(")],
  ["transfer", "target project", "reassign"]);

const CC = P("comment", "CommentController");
const CS = P("comment", "CommentService");
item("jl-comment-author", meth(CC, "public Comment add("), ["authz", "business-logic"],
  "CommentService.add trusts authorId from CommentInput. The service-role integration route sets it legitimately, but the user route binds the request body into CommentInput and only overrides tenant and expense, so a user can post comments as someone else.",
  [meth(CS, "public Comment add("), meth(P("comment", "CommentInput"), "public CommentInput forExpense(")],
  ["author(Id)?", "comments?.{0,80}(spoof|impersonat|attribut)", "CommentInput"]);

const BC = P("billing", "BillingController");
const TF = P("security", "TenantFilter");
item("jl-billing-header", span(BC, '@GetMapping("/plan")', "public List<Invoice> invoices(", 0), "authz",
  "BillingController reads the tenant from the X-Tenant-Id header and passes it to BillingService without checking membership, because TenantFilter skips /api/billing/**; any user can read another tenant's plan and invoices.",
  [meth(TF, "protected boolean shouldNotFilter("), meth(P("billing", "BillingService"), "public Subscription plan(")],
  ["x-tenant-id", "billing", "tenant header"]);
// the billing range ends at the invoices method body
{
  const it = items.at(-1);
  it.endLine = close(BC, it.startLine + 8);
}

// ---- decoys: guarded or intentionally public code that looks suspicious
decoy("jl-decoy-vendor-read", meth(VC, "public List<VendorDto> list(", "public VendorDto get("), "authz", "Vendor list and get carry @PreAuthorize(\"@access.canManage(#tenantId)\"), which ties the path tenant to the caller's tenant and role.");
decoy("jl-decoy-vendor-write", meth(VC, "public VendorDto create(", "public VendorDto restore("), "authz", "Vendor writes are guarded by canManage(#tenantId).");
decoy("jl-decoy-vendor-contacts-bank", meth(VC, "public List<VendorContact> contacts(", "public BankDetailsDto bankDetails("), "authz", "Vendor contacts and masked bank details are guarded by canManage(#tenantId).");
decoy("jl-decoy-expense-get", meth(P("expense", "ExpenseService"), "public Expense get("), "authz", "ExpenseService.get asserts tenant and owner-or-manager.");
decoy("jl-decoy-expense-references", meth(P("expense", "ExpenseService"), "private void checkReferences("), "authz", "Client supplied project and vendor ids are re-validated against the caller's tenant.");
decoy("jl-decoy-receipt-routes", meth(RC, "public List<ReceiptMeta> list(", "public void remove("), "authz", "The four expense receipt routes go through ReceiptService, which calls the checked ExpenseService.get first.");
decoy("jl-decoy-receipt-service", meth(RS, "public List<ReceiptMeta> list(", "public void remove("), "authz", "These ReceiptService methods call ExpenseService.get before touching the repository.");
decoy("jl-decoy-statement-internal", meth(P("statement", "InternalStatementController"), "public StatementView get("), "authz", "/internal/** is restricted to the service role by the URL rule.");
decoy("jl-decoy-statement-user", meth(P("statement", "StatementController"), "public StatementView get(", "public Map<String, String> share("), "authz", "User statement routes authorize tenant and owner-or-manager before building or sharing.");
decoy("jl-decoy-statement-authorize", meth(SS, "private void authorize("), "authz", "StatementService.authorize checks tenant and owner-or-manager.");
decoy("jl-decoy-approval-single", meth(AC, "public Approval approve(", "public Approval reject("), "authz", "Single approve and reject use the authenticated principal as the decider.");
decoy("jl-decoy-approval-service-single", meth(AS, "public Approval approve(", "public Approval reject("), "authz", "approve and reject pass the principal id to the maker-checker rule.");
decoy("jl-decoy-display-name", meth(P("user", "UserService"), "public ProfileDto rename("), "xss", "Text.plain is the right sanitizer for a display name that is rendered as HTML.");
decoy("jl-decoy-safe-segment", meth(TXT, "public static String safeSegment("), "path-traversal", "safeSegment removes separators and dot sequences.");
decoy("jl-decoy-template-publish", meth(MP("templates", "Service"), "public String publish("), "path-traversal", "Template files are written to a tenant directory with Text.safeSegment.");
decoy("jl-decoy-export-download-name", meth(ES, "public String downloadName("), "path-traversal", "The download file name goes through Text.safeSegment.");
decoy("jl-decoy-export-download", meth(EXC, "public ResponseEntity<byte[]> download("), "authz", "Export download loads the job through ExportService.get, which checks tenant and owner-or-manager; the path comes from the stored job.");
decoy("jl-decoy-tenant-filter", meth(TF, "protected void doFilterInternal("), "authz", "TenantFilter rejects an X-Tenant-Id header that differs from the user's tenant.");
decoy("jl-decoy-search-scoped", span(GSS, "expenses.searchByTenant(", "vendors.search(", 1), "authz", "Expense and vendor search are filtered by the caller's tenant (and owner for expenses).");
decoy("jl-decoy-admin-users-list", meth(AUC, "public List<User> list("), "authz", "Single segment /api/admin/users is matched by the ADMIN URL rule.");
decoy("jl-decoy-admin-tenants-list", meth(ATC, "public List<Tenant> list("), "authz", "Single segment /api/admin/tenants is matched by the ADMIN URL rule.");
decoy("jl-decoy-admin-stats", meth(ASC, "public Map<String, Integer> stats("), "authz", "Single segment /api/admin/stats is matched by the ADMIN URL rule.");
decoy("jl-decoy-integration-comment", meth(P("comment", "IntegrationCommentController"), "public Comment relay("), "authz", "The integration route is restricted to the service role and legitimately supplies authorId.");
decoy("jl-decoy-project-source", meth(PS, "private Project requireManaged("), "authz", "requireManaged checks tenant and project manager for the source project.");
decoy("jl-decoy-project-update", meth(PS, "public ProjectDto update("), "authz", "Project update requires the project manager in the caller's tenant.");
decoy("jl-decoy-health", meth(P("web", "HealthController"), "public Map<String, String> health(", "public Map<String, String> status("), "authz", "Health and status are intentionally public and return constant data.");
decoy("jl-decoy-public-plans", meth(P("web", "PublicPlanController"), "public List<PlanListing> plans("), "authz", "The published price list is intentionally public and not tenant data.");
decoy("jl-decoy-category-require", meth(MP("categories", "Service"), "private Category require("), "authz", "The service lookup checks tenant and owner-or-manager although the controller has no inline check.");
decoy("jl-decoy-reminder-owned", meth(MP("reminders", "Service"), "private Reminder owned("), "authz", "Tenant scoped repository lookup plus owner-or-manager check.");
decoy("jl-decoy-reminder-repo", meth(MP("reminders", "Repository"), "public Optional<Reminder> findByTenantAndId("), "authz", "Repository methods always take the tenant id.");
decoy("jl-decoy-tag-controller", meth(MP("tags", "Controller"), "public TagDto update(", "public void delete("), "authz", "The controller checks owner-or-manager on writes after a tenant scoped lookup.");
decoy("jl-decoy-note-linked", meth(MP("notes", "Service"), "private void validate("), "authz", "The client supplied linkedExpenseId is re-validated through ExpenseService.get.");
decoy("jl-decoy-po-vendor-ref", meth(MP("purchase-orders", "Service"), "private void validate("), "authz", "The client supplied vendorRef is re-validated against the caller's tenant.");
decoy("jl-decoy-api-key-own", meth(MP("api-keys", "Service"), "private ApiKey requireOwn("), "authz", "API keys are strictly personal: tenant and owner are checked.");
decoy("jl-decoy-department-writes", meth(MP("departments", "Controller"), "public DepartmentDto create(", "public void delete("), "authz", "Department writes are limited to managers by method security.");

const cleanPaths = [];
for (const m of MODULES) for (const kind of ["", "Dto", "Mapper", "Repository", "Service", "Controller"]) cleanPaths.push(MP(m.key, kind));
for (const n of ["Expense", "ExpenseDto", "ExpenseMapper", "ExpenseRepository", "ExpenseService", "ExpenseController"]) cleanPaths.push(P("expense", n));
for (const n of ["User", "UserRepository", "UserService", "MeController", "ProfileDto"]) cleanPaths.push(P("user", n));
for (const n of ["Tenant", "TenantRepository"]) cleanPaths.push(P("tenant", n));
cleanPaths.sort();

const answer = { fixture: "java-ledger", skill: null, cleanPaths, items, decoys };

// ---------------------------------------------------------------------------------------------------------------
// Route manifest for the proof sweep
// ---------------------------------------------------------------------------------------------------------------
const UNPRIV_READ = { A: 403, B: 403, C: 200, D: 200, E: 403, F: 403 };
const manifest = {
  actors: { crossTenant: ["u-bravo-user1", "u-bravo-mgr", "u-bravo-admin"], sameTenantUnprivileged: "u-alpha-user2" },
  modules: MODULES.map((m) => {
    const seedId = `${m.prefix}-a1`;
    const owner = m.style === "E" ? "u-alpha-mgr" : "u-alpha-user1";
    const writer = m.style === "D" ? "u-alpha-mgr" : owner;
    const body = Object.fromEntries(m.fields.map((q) => [q.name, q.a]));
    const routes = [
      { method: "GET", path: "", kind: "list", unprivStatus: m.style === "E" ? 403 : 200, unprivContainsSeed: m.style === "C" || m.style === "D", controlActor: owner },
      { method: "GET", path: "/{id}", kind: "item", unprivStatus: UNPRIV_READ[m.style], controlActor: owner },
    ];
    if (!m.readOnly) {
      routes.push({ method: "PUT", path: "/{id}", kind: "item", body, unprivStatus: 403, controlActor: writer });
      routes.push({ method: "DELETE", path: "/{id}", kind: "item", unprivStatus: 403, controlActor: null });
    }
    for (const r of m.extra?.routes ?? []) {
      const rw = r.rw ?? "r";
      routes.push({ method: r.method, path: r.path, kind: r.kind ?? "item", unprivStatus: r.kind === "list" ? (m.style === "E" ? 403 : 200) : rw === "w" ? 403 : UNPRIV_READ[m.style],
        ...(r.kind === "list" ? { unprivContainsSeed: false } : {}), controlActor: rw === "w" ? writer : owner });
    }
    return { key: m.key, style: m.style, base: m.base, seedId, owner, routes };
  }),
};

// ---------------------------------------------------------------------------------------------------------------
// Write everything
// ---------------------------------------------------------------------------------------------------------------
rmSync(FIXTURE, { recursive: true, force: true });
const sorted = [...files.keys()].sort();
for (const rel of sorted) {
  const target = join(FIXTURE, rel);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, files.get(rel));
}
const resources = join(PROOF, "src", "test", "resources");
mkdirSync(resources, { recursive: true });
writeFileSync(join(resources, "filler-routes.json"), `${JSON.stringify(manifest, null, 2)}\n`);
writeFileSync(join(FIXTURE, "answer.json"), `${JSON.stringify(answer, null, 2)}\n`);
console.log(`java-ledger: ${sorted.length} files (excluding answer.json), ${items.length} items, ${decoys.length} decoys, ${cleanPaths.length} clean paths`);
