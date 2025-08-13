package com.HYYPS.HYYPS_Backend.userauth.utils;

public class SecurityConstants {
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

    // Cookie settings
    public static final int COOKIE_MAX_AGE = 24 * 60 * 60; // 24 hours in seconds
    public static final boolean COOKIE_HTTP_ONLY = true;
    public static final boolean COOKIE_SECURE = true; // Set to false for development
    public static final String COOKIE_SAME_SITE = "Strict";
}