package com.ledger.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

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
