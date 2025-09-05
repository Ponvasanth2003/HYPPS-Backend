package com.HYYPS.HYYPS_Backend.userauth.utils;

public class SecurityConstants {
    // JWT Cookie Configuration
    public static final String JWT_COOKIE_NAME = "auth_token";
    public static final String CSRF_COOKIE_NAME = "XSRF-TOKEN";
    public static final String CSRF_HEADER_NAME = "X-XSRF-TOKEN";

    // Rate limiting keys
    public static final String RATE_LIMIT_LOGIN = "login:";
    public static final String RATE_LIMIT_SIGNUP = "signup:";
    public static final String RATE_LIMIT_OTP = "otp:";
    public static final String RATE_LIMIT_FORGOT_PASSWORD = "forgot-password:";
    public static final String RATE_LIMIT_SOCIAL_LOGIN = "social-login:";

    // Cache keys
    public static final String CACHE_USER = "user:";
    public static final String CACHE_ROLES = "roles";

    // Security headers
    public static final String HEADER_X_FORWARDED_FOR = "X-Forwarded-For";
    public static final String HEADER_X_REAL_IP = "X-Real-IP";

    // Cookie Security Settings
    public static final int COOKIE_MAX_AGE = 24 * 60 * 60; // 24 hours in seconds
    public static final boolean COOKIE_HTTP_ONLY = true; // Prevent XSS attacks
    public static final boolean COOKIE_SECURE = true; // HTTPS only (set to false for development)
    public static final String COOKIE_SAME_SITE = "Strict"; // CSRF protection

    // Session Cookie Settings (for other uses)
    public static final String SESSION_COOKIE_NAME = "session_id";
    public static final int SESSION_COOKIE_MAX_AGE = 30 * 60; // 30 minutes

    // Remember Me Cookie Settings (if needed in future)
    public static final String REMEMBER_ME_COOKIE_NAME = "remember_me";
    public static final int REMEMBER_ME_MAX_AGE = 30 * 24 * 60 * 60; // 30 days

    // Cookie Security Headers
    public static final String COOKIE_SECURITY_HEADER = "Set-Cookie";

    // Utility constants for cookie operations
    public static final String COOKIE_DELETE_VALUE = "";
    public static final int COOKIE_DELETE_MAX_AGE = 0;

    // Error messages
    public static final String INVALID_COOKIE_ERROR = "Invalid or missing authentication cookie";
    public static final String EXPIRED_COOKIE_ERROR = "Authentication cookie has expired";
    public static final String MISSING_COOKIE_ERROR = "No authentication cookie found";

    // Cookie path settings
    public static final String DEFAULT_COOKIE_PATH = "/";
    public static final String API_COOKIE_PATH = "/api";

    // Private constructor to prevent instantiation
    private SecurityConstants() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }
}