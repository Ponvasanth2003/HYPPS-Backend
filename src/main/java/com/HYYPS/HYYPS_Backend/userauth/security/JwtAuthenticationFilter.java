package com.HYYPS.HYYPS_Backend.userauth.security;

import com.HYYPS.HYYPS_Backend.userauth.utils.SecurityConstants;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * JWT Authentication Filter - HttpOnly Cookie Edition
 *
 * This filter intercepts every request and:
 * 1. Extracts JWT token from HttpOnly cookie
 * 2. Validates the token
 * 3. Extracts user email and roles from token
 * 4. Sets Spring Security authentication context
 *
 * FIXED: Now uses database roles from JWT token instead of enum roles
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider tokenProvider;
    private final SecurityEventLogger securityEventLogger;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            // Extract JWT token from HttpOnly cookie
            String jwt = getJwtFromHttpOnlyCookie(request);

            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                // Extract user email from token
                String email = tokenProvider.getEmailFromToken(jwt);

                // FIXED: Use getRoleNamesFromToken to get database role names as strings
                Set<String> roleNames = tokenProvider.getRoleNamesFromToken(jwt);

                // Convert role names to Spring Security authorities
                // Add "ROLE_" prefix if not already present (Spring Security convention)
                List<SimpleGrantedAuthority> authorities = roleNames.stream()
                        .map(roleName -> {
                            String authority = roleName.startsWith("ROLE_")
                                    ? roleName
                                    : "ROLE_" + roleName;
                            return new SimpleGrantedAuthority(authority);
                        })
                        .collect(Collectors.toList());

                // Create authentication token with user email and authorities
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(email, null, authorities);

                // Set additional details from the request
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set authentication in Spring Security context
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // Set user email in request attribute for logging/tracking
                request.setAttribute("userEmail", email);

                log.debug("Successfully authenticated user: {} with roles: {} from HttpOnly cookie",
                        email, roleNames);

            } else if (jwt != null) {
                // Token exists but is invalid (expired, malformed, etc.)
                String clientIp = getClientIp(request);
                securityEventLogger.logSecurityEvent("INVALID_JWT_COOKIE",
                        "Invalid JWT token in cookie", clientIp);
                log.warn("Invalid JWT token found in HttpOnly cookie from IP: {}", clientIp);

                // Clear invalid cookie
                clearInvalidCookie(response);
            }
        } catch (Exception ex) {
            String clientIp = getClientIp(request);
            log.error("Could not set user authentication in security context from HttpOnly cookie", ex);
            securityEventLogger.logSecurityEvent("JWT_AUTHENTICATION_ERROR",
                    ex.getMessage(), clientIp);

            // Clear the context in case of any error
            SecurityContextHolder.clearContext();

            // Clear potentially corrupted cookie
            clearInvalidCookie(response);
        }

        // Continue filter chain
        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWT token from HttpOnly cookie with enhanced security validation
     *
     * @param request HTTP request
     * @return JWT token string or null if not found/invalid
     */
    private String getJwtFromHttpOnlyCookie(HttpServletRequest request) {
        // Check if cookies exist
        if (request.getCookies() == null) {
            log.trace("No cookies found in request");
            return null;
        }

        // Search for JWT cookie
        for (Cookie cookie : request.getCookies()) {
            if (SecurityConstants.JWT_COOKIE_NAME.equals(cookie.getName())) {
                String tokenValue = cookie.getValue();

                // Additional security validation
                if (tokenValue != null && !tokenValue.trim().isEmpty() && !tokenValue.equals("")) {
                    // Basic format validation - JWT should have 3 parts separated by dots
                    String[] parts = tokenValue.split("\\.");
                    if (parts.length == 3) {
                        log.trace("Valid JWT token format found in HttpOnly cookie");
                        return tokenValue;
                    } else {
                        log.warn("Invalid JWT token format in HttpOnly cookie. Parts: {}", parts.length);
                        return null;
                    }
                } else {
                    log.trace("Empty or null JWT token value in HttpOnly cookie");
                    return null;
                }
            }
        }

        log.trace("No JWT token found in HttpOnly cookies");
        return null;
    }

    /**
     * Clear invalid or corrupted cookie from response
     *
     * @param response HTTP response
     */
    private void clearInvalidCookie(HttpServletResponse response) {
        try {
            // Create cookie with empty value and max-age 0 to delete it
            Cookie clearCookie = new Cookie(SecurityConstants.JWT_COOKIE_NAME, "");
            clearCookie.setHttpOnly(true);
            clearCookie.setSecure(true);
            clearCookie.setPath(SecurityConstants.DEFAULT_COOKIE_PATH);
            clearCookie.setMaxAge(0); // Delete immediately

            response.addCookie(clearCookie);

            // Also clear via Set-Cookie header for better browser compatibility
            response.addHeader(SecurityConstants.COOKIE_SECURITY_HEADER,
                    String.format("%s=; Path=%s; Max-Age=0; HttpOnly; Secure; SameSite=%s",
                            SecurityConstants.JWT_COOKIE_NAME,
                            SecurityConstants.DEFAULT_COOKIE_PATH,
                            SecurityConstants.COOKIE_SAME_SITE
                    )
            );

            log.debug("Cleared invalid JWT cookie");
        } catch (Exception e) {
            log.error("Failed to clear invalid cookie: {}", e.getMessage());
        }
    }

    /**
     * Extract client IP address for security logging
     * Handles proxy headers (X-Forwarded-For, X-Real-IP)
     *
     * @param request HTTP request
     * @return Client IP address
     */
    private String getClientIp(HttpServletRequest request) {
        // Check X-Forwarded-For header (for requests through proxy/load balancer)
        String xForwardedFor = request.getHeader(SecurityConstants.HEADER_X_FORWARDED_FOR);
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            // X-Forwarded-For can contain multiple IPs, take the first one
            return xForwardedFor.split(",")[0].trim();
        }

        // Check X-Real-IP header (alternative proxy header)
        String xRealIp = request.getHeader(SecurityConstants.HEADER_X_REAL_IP);
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        // Fall back to remote address
        return request.getRemoteAddr();
    }

    /**
     * Determine if this filter should NOT be applied to the request
     * Skip JWT authentication for public endpoints
     *
     * @param request HTTP request
     * @return true if filter should be skipped, false otherwise
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();

        // Skip JWT authentication for these public endpoints
        boolean shouldSkip = path.startsWith("/api/auth/signup") ||
                path.startsWith("/api/auth/login") ||
                path.startsWith("/api/auth/verify-otp") ||
                path.startsWith("/api/auth/resend-otp") ||
                path.startsWith("/api/auth/forgot-password") ||
                path.startsWith("/api/auth/reset-password") ||
                path.startsWith("/api/auth/social-login") ||
                path.startsWith("/api/auth/roles") ||
                path.startsWith("/api/health") ||
                path.startsWith("/actuator") ||
                path.startsWith("/swagger-ui") ||
                path.startsWith("/v3/api-docs") ||
                path.startsWith("/api-docs") ||
                path.startsWith("/swagger-resources") ||
                path.startsWith("/webjars") ||
                path.equals("/");

        if (shouldSkip) {
            log.trace("Skipping JWT filter for public path: {}", path);
        }

        return shouldSkip;
    }
}