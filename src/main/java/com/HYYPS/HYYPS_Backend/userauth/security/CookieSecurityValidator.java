package com.HYYPS.HYYPS_Backend.userauth.security;

import com.HYYPS.HYYPS_Backend.userauth.utils.SecurityConstants;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Base64;

@Component
@RequiredArgsConstructor
@Slf4j
public class CookieSecurityValidator {

    private final JwtTokenProvider jwtTokenProvider;

    /**
     * Comprehensive validation of HttpOnly JWT cookie
     */
    public ValidationResult validateJwtCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            return ValidationResult.failure("No cookies present in request");
        }

        Cookie jwtCookie = Arrays.stream(cookies)
                .filter(cookie -> SecurityConstants.JWT_COOKIE_NAME.equals(cookie.getName()))
                .findFirst()
                .orElse(null);

        if (jwtCookie == null) {
            return ValidationResult.failure("JWT cookie not found");
        }

        return validateJwtCookieContent(jwtCookie);
    }

    /**
     * Validate the content and structure of JWT cookie
     */
    private ValidationResult validateJwtCookieContent(Cookie jwtCookie) {
        String tokenValue = jwtCookie.getValue();

        // Check for null or empty
        if (tokenValue == null || tokenValue.trim().isEmpty()) {
            return ValidationResult.failure("JWT cookie value is null or empty");
        }

        // Check for placeholder values that might indicate cleared cookie
        if ("".equals(tokenValue) || "deleted".equals(tokenValue) || "null".equals(tokenValue)) {
            return ValidationResult.failure("JWT cookie contains placeholder value");
        }

        // Validate JWT structure (should have 3 parts separated by dots)
        String[] jwtParts = tokenValue.split("\\.");
        if (jwtParts.length != 3) {
            log.warn("Invalid JWT structure. Expected 3 parts, found: {}", jwtParts.length);
            return ValidationResult.failure("Invalid JWT structure");
        }

        // Validate each part is valid Base64
        for (int i = 0; i < jwtParts.length; i++) {
            if (!isValidBase64(jwtParts[i])) {
                log.warn("Invalid Base64 encoding in JWT part {}", i);
                return ValidationResult.failure("Invalid JWT encoding");
            }
        }

        // Validate JWT token using TokenProvider
        try {
            if (!jwtTokenProvider.validateToken(tokenValue)) {
                return ValidationResult.failure("JWT token validation failed");
            }
        } catch (Exception e) {
            log.error("JWT token validation error: {}", e.getMessage());
            return ValidationResult.failure("JWT token validation error: " + e.getMessage());
        }

        // Additional security checks
        try {
            String email = jwtTokenProvider.getEmailFromToken(tokenValue);
            if (email == null || email.trim().isEmpty()) {
                return ValidationResult.failure("No email found in JWT token");
            }

            // Check if token is expired
            if (jwtTokenProvider.getExpirationDateFromToken(tokenValue).before(new java.util.Date())) {
                return ValidationResult.failure("JWT token is expired");
            }

        } catch (Exception e) {
            log.error("Error extracting information from JWT: {}", e.getMessage());
            return ValidationResult.failure("Error processing JWT token");
        }

        return ValidationResult.success("JWT cookie validation successful");
    }

    /**
     * Validate if string is valid Base64 (with URL-safe characters)
     */
    private boolean isValidBase64(String base64String) {
        try {
            // JWT uses Base64 URL-safe encoding, so we need to handle both
            Base64.getUrlDecoder().decode(base64String);
            return true;
        } catch (IllegalArgumentException e) {
            try {
                // Try regular Base64 as fallback
                Base64.getDecoder().decode(base64String);
                return true;
            } catch (IllegalArgumentException e2) {
                return false;
            }
        }
    }

    /**
     * Check cookie security attributes (for debugging/monitoring)
     */
    public CookieSecurityInfo analyzeCookieSecurity(Cookie cookie) {
        return CookieSecurityInfo.builder()
                .name(cookie.getName())
                .hasValue(cookie.getValue() != null && !cookie.getValue().isEmpty())
                .isHttpOnly(cookie.isHttpOnly())
                .isSecure(cookie.getSecure())
                .path(cookie.getPath())
                .domain(cookie.getDomain())
                .maxAge(cookie.getMaxAge())
                .build();
    }

    /**
     * Validation result wrapper
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String message;

        private ValidationResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }

        public static ValidationResult success(String message) {
            return new ValidationResult(true, message);
        }

        public static ValidationResult failure(String message) {
            return new ValidationResult(false, message);
        }

        public boolean isValid() {
            return valid;
        }

        public String getMessage() {
            return message;
        }
    }

    /**
     * Cookie security information for monitoring
     */
    public static class CookieSecurityInfo {
        private final String name;
        private final boolean hasValue;
        private final boolean isHttpOnly;
        private final boolean isSecure;
        private final String path;
        private final String domain;
        private final int maxAge;

        public CookieSecurityInfo(String name, boolean hasValue, boolean isHttpOnly,
                                  boolean isSecure, String path, String domain, int maxAge) {
            this.name = name;
            this.hasValue = hasValue;
            this.isHttpOnly = isHttpOnly;
            this.isSecure = isSecure;
            this.path = path;
            this.domain = domain;
            this.maxAge = maxAge;
        }

        public static CookieSecurityInfoBuilder builder() {
            return new CookieSecurityInfoBuilder();
        }

        // Builder pattern
        public static class CookieSecurityInfoBuilder {
            private String name;
            private boolean hasValue;
            private boolean isHttpOnly;
            private boolean isSecure;
            private String path;
            private String domain;
            private int maxAge;

            public CookieSecurityInfoBuilder name(String name) {
                this.name = name;
                return this;
            }

            public CookieSecurityInfoBuilder hasValue(boolean hasValue) {
                this.hasValue = hasValue;
                return this;
            }

            public CookieSecurityInfoBuilder isHttpOnly(boolean isHttpOnly) {
                this.isHttpOnly = isHttpOnly;
                return this;
            }

            public CookieSecurityInfoBuilder isSecure(boolean isSecure) {
                this.isSecure = isSecure;
                return this;
            }

            public CookieSecurityInfoBuilder path(String path) {
                this.path = path;
                return this;
            }

            public CookieSecurityInfoBuilder domain(String domain) {
                this.domain = domain;
                return this;
            }

            public CookieSecurityInfoBuilder maxAge(int maxAge) {
                this.maxAge = maxAge;
                return this;
            }

            public CookieSecurityInfo build() {
                return new CookieSecurityInfo(name, hasValue, isHttpOnly, isSecure, path, domain, maxAge);
            }
        }

        // Getters
        public String getName() { return name; }
        public boolean hasValue() { return hasValue; }
        public boolean isHttpOnly() { return isHttpOnly; }
        public boolean isSecure() { return isSecure; }
        public String getPath() { return path; }
        public String getDomain() { return domain; }
        public int getMaxAge() { return maxAge; }
    }
}