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
import java.util.stream.Collectors;

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
                String email = tokenProvider.getEmailFromToken(jwt);
                List<SimpleGrantedAuthority> authorities = tokenProvider.getRolesFromToken(jwt)
                        .stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                        .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(email, null, authorities);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);

                // Set user email in request for logging purposes
                request.setAttribute("userEmail", email);

                log.debug("Successfully authenticated user: {} from HttpOnly cookie", email);
            } else if (jwt != null) {
                // Token exists but is invalid
                String clientIp = getClientIp(request);
                securityEventLogger.logSecurityEvent("INVALID_JWT_COOKIE", "Invalid JWT token in cookie", clientIp);
                log.warn("Invalid JWT token found in HttpOnly cookie from IP: {}", clientIp);

                // Clear invalid cookie
                clearInvalidCookie(response);
            }
        } catch (Exception ex) {
            String clientIp = getClientIp(request);
            log.error("Could not set user authentication in security context from HttpOnly cookie", ex);
            securityEventLogger.logSecurityEvent("JWT_AUTHENTICATION_ERROR", ex.getMessage(), clientIp);

            // Clear the context in case of any error
            SecurityContextHolder.clearContext();

            // Clear potentially corrupted cookie
            clearInvalidCookie(response);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWT token from HttpOnly cookie with enhanced security validation
     */
    private String getJwtFromHttpOnlyCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }

        for (Cookie cookie : request.getCookies()) {
            if (SecurityConstants.JWT_COOKIE_NAME.equals(cookie.getName())) {
                String tokenValue = cookie.getValue();

                // Additional security validation
                if (tokenValue != null && !tokenValue.trim().isEmpty() && !tokenValue.equals("")) {
                    // Basic format validation - JWT should have 3 parts separated by dots
                    String[] parts = tokenValue.split("\\.");
                    if (parts.length == 3) {
                        log.debug("Valid JWT token format found in HttpOnly cookie");
                        return tokenValue;
                    } else {
                        log.warn("Invalid JWT token format in HttpOnly cookie. Parts: {}", parts.length);
                        return null;
                    }
                } else {
                    log.debug("Empty or null JWT token value in HttpOnly cookie");
                    return null;
                }
            }
        }

        log.debug("No JWT token found in HttpOnly cookies");
        return null;
    }

    /**
     * Clear invalid or corrupted cookie
     */
    private void clearInvalidCookie(HttpServletResponse response) {
        try {
            Cookie clearCookie = new Cookie(SecurityConstants.JWT_COOKIE_NAME, "");
            clearCookie.setHttpOnly(true);
            clearCookie.setSecure(true);
            clearCookie.setPath(SecurityConstants.DEFAULT_COOKIE_PATH);
            clearCookie.setMaxAge(0); // Delete immediately

            response.addCookie(clearCookie);

            // Also clear via header for better browser compatibility
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
     */
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader(SecurityConstants.HEADER_X_FORWARDED_FOR);
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader(SecurityConstants.HEADER_X_REAL_IP);
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }

    /**
     * Check if the request should be filtered (skip for certain paths)
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();

        // Skip JWT authentication for public endpoints
        return path.startsWith("/api/auth/signup") ||
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
                path.equals("/");
    }
}