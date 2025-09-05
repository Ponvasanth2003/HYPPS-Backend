package com.HYYPS.HYYPS_Backend.userauth.security;

import com.HYYPS.HYYPS_Backend.userauth.utils.SecurityConstants;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class CookieUtil {

    @Value("${app.cookie.secure:true}")
    private boolean cookieSecure;

    @Value("${app.cookie.domain:}")
    private String cookieDomain;

    @Value("${app.cookie.path:/}")
    private String cookiePath;

    @Value("${app.environment:production}")
    private String environment;

    private final JwtTokenProvider jwtTokenProvider;

    /**
     * Set JWT token as HttpOnly + Secure cookie
     */
    public void setJwtCookie(HttpServletResponse response, String token) {
        // Determine if we should use secure cookies (false only in development)
        boolean useSecure = cookieSecure && !"development".equalsIgnoreCase(environment);

        Cookie jwtCookie = new Cookie(SecurityConstants.JWT_COOKIE_NAME, token);
        jwtCookie.setHttpOnly(SecurityConstants.COOKIE_HTTP_ONLY); // Prevent XSS
        jwtCookie.setSecure(useSecure); // HTTPS only in production
        jwtCookie.setPath(cookiePath); // Cookie scope
        jwtCookie.setMaxAge(SecurityConstants.COOKIE_MAX_AGE); // 24 hours

        if (!cookieDomain.isEmpty()) {
            jwtCookie.setDomain(cookieDomain);
        }

        // Add cookie via response
        response.addCookie(jwtCookie);

        // Also set via header for better cross-browser compatibility and SameSite attribute
        StringBuilder cookieHeader = new StringBuilder();
        cookieHeader.append(SecurityConstants.JWT_COOKIE_NAME).append("=").append(token);
        cookieHeader.append("; Path=").append(cookiePath);
        cookieHeader.append("; Max-Age=").append(SecurityConstants.COOKIE_MAX_AGE);
        cookieHeader.append("; HttpOnly"); // XSS protection

        if (useSecure) {
            cookieHeader.append("; Secure"); // HTTPS only
        }

        cookieHeader.append("; SameSite=").append(SecurityConstants.COOKIE_SAME_SITE); // CSRF protection

        if (!cookieDomain.isEmpty()) {
            cookieHeader.append("; Domain=").append(cookieDomain);
        }

        response.addHeader("Set-Cookie", cookieHeader.toString());
        log.debug("JWT cookie set with HttpOnly={}, Secure={}, SameSite={}",
                SecurityConstants.COOKIE_HTTP_ONLY, useSecure, SecurityConstants.COOKIE_SAME_SITE);
    }

    /**
     * Clear JWT cookie by setting empty value and Max-Age=0
     */
    public void clearJwtCookie(HttpServletResponse response) {
        boolean useSecure = cookieSecure && !"development".equalsIgnoreCase(environment);

        Cookie jwtCookie = new Cookie(SecurityConstants.JWT_COOKIE_NAME, "");
        jwtCookie.setHttpOnly(SecurityConstants.COOKIE_HTTP_ONLY);
        jwtCookie.setSecure(useSecure);
        jwtCookie.setPath(cookiePath);
        jwtCookie.setMaxAge(0); // Delete immediately

        if (!cookieDomain.isEmpty()) {
            jwtCookie.setDomain(cookieDomain);
        }

        response.addCookie(jwtCookie);

        // Also clear via header for better browser compatibility
        StringBuilder cookieHeader = new StringBuilder();
        cookieHeader.append(SecurityConstants.JWT_COOKIE_NAME).append("=");
        cookieHeader.append("; Path=").append(cookiePath);
        cookieHeader.append("; Max-Age=0");
        cookieHeader.append("; HttpOnly");

        if (useSecure) {
            cookieHeader.append("; Secure");
        }

        cookieHeader.append("; SameSite=").append(SecurityConstants.COOKIE_SAME_SITE);

        if (!cookieDomain.isEmpty()) {
            cookieHeader.append("; Domain=").append(cookieDomain);
        }

        response.addHeader("Set-Cookie", cookieHeader.toString());
        log.debug("JWT cookie cleared");
    }

    /**
     * Extract JWT token from HttpOnly cookie
     */
    public String getJwtFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }

        for (Cookie cookie : request.getCookies()) {
            if (SecurityConstants.JWT_COOKIE_NAME.equals(cookie.getName())) {
                String token = cookie.getValue();
                // Additional validation - ensure token is not empty or null
                if (token != null && !token.trim().isEmpty()) {
                    return token;
                }
            }
        }
        return null;
    }

    /**
     * Check if request has a valid JWT cookie
     */
    public boolean hasValidJwtCookie(HttpServletRequest request) {
        String token = getJwtFromCookie(request);
        return token != null && jwtTokenProvider.validateToken(token);
    }

    /**
     * Set a secure session cookie (for other purposes)
     */
    public void setSecureCookie(HttpServletResponse response, String cookieName,
                                String cookieValue, int maxAgeSeconds) {
        boolean useSecure = cookieSecure && !"development".equalsIgnoreCase(environment);

        Cookie cookie = new Cookie(cookieName, cookieValue);
        cookie.setHttpOnly(true); // Always HttpOnly for security
        cookie.setSecure(useSecure);
        cookie.setPath(cookiePath);
        cookie.setMaxAge(maxAgeSeconds);

        if (!cookieDomain.isEmpty()) {
            cookie.setDomain(cookieDomain);
        }

        response.addCookie(cookie);

        // Also set via header for SameSite attribute
        StringBuilder cookieHeader = new StringBuilder();
        cookieHeader.append(cookieName).append("=").append(cookieValue);
        cookieHeader.append("; Path=").append(cookiePath);
        cookieHeader.append("; Max-Age=").append(maxAgeSeconds);
        cookieHeader.append("; HttpOnly");

        if (useSecure) {
            cookieHeader.append("; Secure");
        }

        cookieHeader.append("; SameSite=").append(SecurityConstants.COOKIE_SAME_SITE);

        if (!cookieDomain.isEmpty()) {
            cookieHeader.append("; Domain=").append(cookieDomain);
        }

        response.addHeader("Set-Cookie", cookieHeader.toString());
        log.debug("Secure cookie set: {}", cookieName);
    }

    /**
     * Clear any secure cookie
     */
    public void clearSecureCookie(HttpServletResponse response, String cookieName) {
        boolean useSecure = cookieSecure && !"development".equalsIgnoreCase(environment);

        Cookie cookie = new Cookie(cookieName, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(useSecure);
        cookie.setPath(cookiePath);
        cookie.setMaxAge(0);

        if (!cookieDomain.isEmpty()) {
            cookie.setDomain(cookieDomain);
        }

        response.addCookie(cookie);

        // Also clear via header
        StringBuilder cookieHeader = new StringBuilder();
        cookieHeader.append(cookieName).append("=");
        cookieHeader.append("; Path=").append(cookiePath);
        cookieHeader.append("; Max-Age=0");
        cookieHeader.append("; HttpOnly");

        if (useSecure) {
            cookieHeader.append("; Secure");
        }

        cookieHeader.append("; SameSite=").append(SecurityConstants.COOKIE_SAME_SITE);

        if (!cookieDomain.isEmpty()) {
            cookieHeader.append("; Domain=").append(cookieDomain);
        }

        response.addHeader("Set-Cookie", cookieHeader.toString());
        log.debug("Secure cookie cleared: {}", cookieName);
    }

    /**
     * Get value from any HttpOnly cookie
     */
    public String getCookieValue(HttpServletRequest request, String cookieName) {
        if (request.getCookies() == null) {
            return null;
        }

        for (Cookie cookie : request.getCookies()) {
            if (cookieName.equals(cookie.getName())) {
                String value = cookie.getValue();
                if (value != null && !value.trim().isEmpty()) {
                    return value;
                }
            }
        }
        return null;
    }
}