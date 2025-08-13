package com.HYYPS.HYYPS_Backend.userauth.controller;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.security.CookieUtil;
import com.HYYPS.HYYPS_Backend.userauth.security.SecurityEventLogger;
import com.HYYPS.HYYPS_Backend.userauth.service.AuthService;
import com.HYYPS.HYYPS_Backend.userauth.service.AuthServiceCircuitBreaker;
import com.HYYPS.HYYPS_Backend.userauth.service.RateLimitService;
import com.HYYPS.HYYPS_Backend.userauth.service.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "authentication-api", description = "Handles Authentication APIs")
public class AuthController {

    private final AuthService authService;
    private final AuthServiceCircuitBreaker authServiceCircuitBreaker; // Circuit breaker integration
    private final RoleService roleService;
    private final RateLimitService rateLimitService;
    private final SecurityEventLogger securityEventLogger;
    private final CookieUtil cookieUtil;

    @PostMapping("/signup")
    @Operation(
            summary = "Initiate user signup",
            description = "Start the user registration process by sending OTP to the provided email address"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OTP sent successfully"),
            @ApiResponse(responseCode = "409", description = "Email already exists"),
            @ApiResponse(responseCode = "429", description = "Rate limit exceeded")
    })
    public ResponseEntity<ApiResponseDto<Void>> signup(
            @Valid @RequestBody SignupRequestDto request,
            HttpServletRequest httpRequest) {

        String clientIp = getClientIp(httpRequest);
        String rateLimitKey = "signup:" + clientIp;

        // Rate limiting
        if (rateLimitService.isRateLimited(rateLimitKey, 5, 3)) {
            securityEventLogger.logSecurityEvent("SIGNUP_RATE_LIMIT_EXCEEDED", request.getEmail(), clientIp);
            return ResponseEntity.status(429)
                    .body(ApiResponseDto.error("Too many signup attempts. Please try again later."));
        }

        log.info("Signup request received for email: {} from IP: {}", request.getEmail(), clientIp);
        securityEventLogger.logSecurityEvent("SIGNUP_ATTEMPT", request.getEmail(), clientIp);

        ApiResponseDto<Void> response = authService.initiateSignup(request, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-otp")
    @Operation(
            summary = "Verify OTP, create account, and auto-login",
            description = "Verify the OTP sent to email, create user account, generate JWT token, and automatically log in the user"
    )
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> verifyOtp(
            @Valid @RequestBody OtpVerificationDto request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        String clientIp = getClientIp(httpRequest);
        String rateLimitKey = "verify-otp:" + request.getEmail();

        // Rate limiting
        if (rateLimitService.isRateLimited(rateLimitKey, 5, 5)) {
            securityEventLogger.logSecurityEvent("OTP_VERIFICATION_RATE_LIMIT_EXCEEDED", request.getEmail(), clientIp);
            return ResponseEntity.status(429)
                    .body(ApiResponseDto.error("Too many OTP verification attempts. Please try again later."));
        }

        log.info("OTP verification request for email: {} from IP: {}", request.getEmail(), clientIp);
        securityEventLogger.logSecurityEvent("OTP_VERIFICATION_ATTEMPT", request.getEmail(), clientIp);

        ApiResponseDto<Map<String, Object>> response = authService.verifyOtpCreateAccountAndLogin(request, httpResponse);

        if (response.isSuccess()) {
            securityEventLogger.logSecurityEvent("ACCOUNT_CREATED_AND_LOGGED_IN", request.getEmail(), clientIp);
            log.info("Account created and user automatically logged in for email: {}", request.getEmail());
        }

        return ResponseEntity.ok(response);
    }

    /**
     * UPDATED: Login endpoint with Circuit Breaker support
     *
     * PRODUCTION FEATURES:
     * 1. Circuit Breaker protection for high-availability
     * 2. Graceful degradation when services are unavailable
     * 3. Automatic retry with exponential backoff
     * 4. Async processing for better performance
     */
    @PostMapping("/login")
    @Operation(
            summary = "User login with circuit breaker protection",
            description = "Authenticate user with email and password using circuit breaker pattern for high availability"
    )
    public ResponseEntity<CompletableFuture<ApiResponseDto<Map<String, Object>>>> login(
            @Valid @RequestBody LoginRequestDto request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        String clientIp = getClientIp(httpRequest);
        String rateLimitKey = "login:" + request.getEmail();

        // Rate limiting
        if (rateLimitService.isRateLimited(rateLimitKey, 15, 5)) {
            securityEventLogger.logSecurityEvent("LOGIN_RATE_LIMIT_EXCEEDED", request.getEmail(), clientIp);
            CompletableFuture<ApiResponseDto<Map<String, Object>>> errorResponse =
                    CompletableFuture.completedFuture(
                            ApiResponseDto.error("Too many login attempts. Please try again later.")
                    );
            return ResponseEntity.status(429).body(errorResponse);
        }

        log.info("Login request for email: {} from IP: {}", request.getEmail(), clientIp);
        securityEventLogger.logSecurityEvent("LOGIN_ATTEMPT", request.getEmail(), clientIp);

        // Use circuit breaker for production resilience
        CompletableFuture<ApiResponseDto<Map<String, Object>>> futureResponse =
                authServiceCircuitBreaker.loginWithCircuitBreaker(request, httpResponse);

        // Add success/failure logging asynchronously
        futureResponse.whenComplete((response, throwable) -> {
            if (throwable == null && response.isSuccess()) {
                securityEventLogger.logSecurityEvent("LOGIN_SUCCESS", request.getEmail(), clientIp);
                log.info("Login successful for email: {}", request.getEmail());
            } else {
                securityEventLogger.logSecurityEvent("LOGIN_FAILED", request.getEmail(), clientIp);
                log.warn("Login failed for email: {}", request.getEmail());
            }
        });

        return ResponseEntity.ok(futureResponse);
    }

    /**
     * FALLBACK: Synchronous login for clients that don't support async
     */
    @PostMapping("/login/sync")
    @Operation(
            summary = "Synchronous user login",
            description = "Authenticate user synchronously - use this if your client doesn't support async responses"
    )
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> loginSync(
            @Valid @RequestBody LoginRequestDto request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        String clientIp = getClientIp(httpRequest);
        String rateLimitKey = "login:" + request.getEmail();

        // Rate limiting
        if (rateLimitService.isRateLimited(rateLimitKey, 15, 5)) {
            securityEventLogger.logSecurityEvent("LOGIN_RATE_LIMIT_EXCEEDED", request.getEmail(), clientIp);
            return ResponseEntity.status(429)
                    .body(ApiResponseDto.error("Too many login attempts. Please try again later."));
        }

        log.info("Sync login request for email: {} from IP: {}", request.getEmail(), clientIp);
        securityEventLogger.logSecurityEvent("LOGIN_ATTEMPT", request.getEmail(), clientIp);

        // Use regular service for synchronous login
        ApiResponseDto<Map<String, Object>> response = authService.login(request, httpResponse);

        if (response.isSuccess()) {
            securityEventLogger.logSecurityEvent("LOGIN_SUCCESS", request.getEmail(), clientIp);
        } else {
            securityEventLogger.logSecurityEvent("LOGIN_FAILED", request.getEmail(), clientIp);
        }

        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    @Operation(
            summary = "User logout",
            description = "Clear JWT token from HttpOnly cookie and logout user"
    )
    public ResponseEntity<ApiResponseDto<Void>> logout(
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        String clientIp = getClientIp(httpRequest);
        String userEmail = httpRequest.getRemoteUser();

        // Clear the JWT cookie
        cookieUtil.clearJwtCookie(httpResponse);

        log.info("Logout request from IP: {}", clientIp);
        if (userEmail != null) {
            securityEventLogger.logSecurityEvent("LOGOUT", userEmail, clientIp);
        }

        return ResponseEntity.ok(ApiResponseDto.success("Logout successful"));
    }

    @PostMapping("/refresh-token")
    @Operation(
            summary = "Refresh JWT token",
            description = "Refresh the JWT token using the existing token in HttpOnly cookie"
    )
    public ResponseEntity<ApiResponseDto<Void>> refreshToken(
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        String clientIp = getClientIp(httpRequest);

        ApiResponseDto<Void> response = authService.refreshToken(httpRequest, httpResponse);

        if (response.isSuccess()) {
            String userEmail = httpRequest.getRemoteUser();
            if (userEmail != null) {
                securityEventLogger.logSecurityEvent("TOKEN_REFRESHED", userEmail, clientIp);
            }
        }

        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-otp")
    @Operation(
            summary = "Resend OTP",
            description = "Resend OTP to the specified email address"
    )
    public ResponseEntity<ApiResponseDto<Void>> resendOtp(
            @RequestParam String email,
            HttpServletRequest httpRequest) {

        String clientIp = getClientIp(httpRequest);
        String rateLimitKey = "resend-otp:" + email;

        // Rate limiting
        if (rateLimitService.isRateLimited(rateLimitKey, 5, 3)) {
            securityEventLogger.logSecurityEvent("RESEND_OTP_RATE_LIMIT_EXCEEDED", email, clientIp);
            return ResponseEntity.status(429)
                    .body(ApiResponseDto.error("Too many resend OTP attempts. Please try again later."));
        }

        log.info("Resend OTP request for email: {} from IP: {}", email, clientIp);
        securityEventLogger.logSecurityEvent("RESEND_OTP_ATTEMPT", email, clientIp);

        ApiResponseDto<Void> response = authService.resendOtp(email, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    @Operation(
            summary = "Forgot password",
            description = "Send password reset OTP to the specified email address"
    )
    public ResponseEntity<ApiResponseDto<Void>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequestDto request,
            HttpServletRequest httpRequest) {

        String clientIp = getClientIp(httpRequest);
        String rateLimitKey = "forgot-password:" + request.getEmail();

        // Rate limiting
        if (rateLimitService.isRateLimited(rateLimitKey, 10, 3)) {
            securityEventLogger.logSecurityEvent("FORGOT_PASSWORD_RATE_LIMIT_EXCEEDED", request.getEmail(), clientIp);
            return ResponseEntity.status(429)
                    .body(ApiResponseDto.error("Too many password reset attempts. Please try again later."));
        }

        log.info("Forgot password request for email: {} from IP: {}", request.getEmail(), clientIp);
        securityEventLogger.logSecurityEvent("FORGOT_PASSWORD_ATTEMPT", request.getEmail(), clientIp);

        ApiResponseDto<Void> response = authService.forgotPassword(request, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/reset-password")
    @Operation(
            summary = "Reset password",
            description = "Reset password using OTP verification"
    )
    public ResponseEntity<ApiResponseDto<Void>> resetPassword(
            @Valid @RequestBody ResetPasswordRequestDto request,
            HttpServletRequest httpRequest) {

        String clientIp = getClientIp(httpRequest);
        String rateLimitKey = "reset-password:" + request.getEmail();

        // Rate limiting
        if (rateLimitService.isRateLimited(rateLimitKey, 15, 5)) {
            securityEventLogger.logSecurityEvent("RESET_PASSWORD_RATE_LIMIT_EXCEEDED", request.getEmail(), clientIp);
            return ResponseEntity.status(429)
                    .body(ApiResponseDto.error("Too many password reset attempts. Please try again later."));
        }

        log.info("Reset password request for email: {} from IP: {}", request.getEmail(), clientIp);
        securityEventLogger.logSecurityEvent("RESET_PASSWORD_ATTEMPT", request.getEmail(), clientIp);

        ApiResponseDto<Void> response = authService.resetPassword(request);

        if (response.isSuccess()) {
            securityEventLogger.logSecurityEvent("PASSWORD_RESET_SUCCESS", request.getEmail(), clientIp);
        }

        return ResponseEntity.ok(response);
    }

    /**
     * UPDATED: Social login with Circuit Breaker support
     */
    @PostMapping("/social-login")
    @Operation(
            summary = "Social login/signup with circuit breaker protection",
            description = "Login or signup using Google/Facebook authentication with high availability support"
    )
    public ResponseEntity<CompletableFuture<ApiResponseDto<Map<String, Object>>>> socialLogin(
            @Valid @RequestBody SocialLoginRequestDto request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        String clientIp = getClientIp(httpRequest);
        String rateLimitKey = "social-login:" + clientIp;

        // Rate limiting
        if (rateLimitService.isRateLimited(rateLimitKey, 10, 10)) {
            securityEventLogger.logSecurityEvent("SOCIAL_LOGIN_RATE_LIMIT_EXCEEDED", request.getEmail(), clientIp);
            CompletableFuture<ApiResponseDto<Map<String, Object>>> errorResponse =
                    CompletableFuture.completedFuture(
                            ApiResponseDto.error("Too many social login attempts. Please try again later.")
                    );
            return ResponseEntity.status(429).body(errorResponse);
        }

        log.info("Social login request for provider: {} and email: {} from IP: {}",
                request.getProvider(), request.getEmail(), clientIp);
        securityEventLogger.logSecurityEvent("SOCIAL_LOGIN_ATTEMPT", request.getEmail(), clientIp);

        // Use circuit breaker for production resilience
        CompletableFuture<ApiResponseDto<Map<String, Object>>> futureResponse =
                authServiceCircuitBreaker.socialLoginWithCircuitBreaker(request, httpResponse);

        // Add success/failure logging asynchronously
        futureResponse.whenComplete((response, throwable) -> {
            if (throwable == null && response.isSuccess()) {
                securityEventLogger.logSecurityEvent("SOCIAL_LOGIN_SUCCESS", request.getEmail(), clientIp);
                log.info("Social login successful for email: {}", request.getEmail());
            } else {
                securityEventLogger.logSecurityEvent("SOCIAL_LOGIN_FAILED", request.getEmail(), clientIp);
                log.warn("Social login failed for email: {}", request.getEmail());
            }
        });

        return ResponseEntity.ok(futureResponse);
    }

    /**
     * FALLBACK: Synchronous social login
     */
    @PostMapping("/social-login/sync")
    @Operation(
            summary = "Synchronous social login",
            description = "Social login without async processing - use if your client doesn't support async responses"
    )
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> socialLoginSync(
            @Valid @RequestBody SocialLoginRequestDto request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        String clientIp = getClientIp(httpRequest);
        String rateLimitKey = "social-login:" + clientIp;

        // Rate limiting
        if (rateLimitService.isRateLimited(rateLimitKey, 10, 10)) {
            securityEventLogger.logSecurityEvent("SOCIAL_LOGIN_RATE_LIMIT_EXCEEDED", request.getEmail(), clientIp);
            return ResponseEntity.status(429)
                    .body(ApiResponseDto.error("Too many social login attempts. Please try again later."));
        }

        log.info("Sync social login request for provider: {} and email: {} from IP: {}",
                request.getProvider(), request.getEmail(), clientIp);
        securityEventLogger.logSecurityEvent("SOCIAL_LOGIN_ATTEMPT", request.getEmail(), clientIp);

        ApiResponseDto<Map<String, Object>> response = authService.socialLogin(request, httpResponse);

        if (response.isSuccess()) {
            securityEventLogger.logSecurityEvent("SOCIAL_LOGIN_SUCCESS", request.getEmail(), clientIp);
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/roles")
    @Operation(
            summary = "Get all available roles",
            description = "Retrieve all available roles in the system"
    )
    public ResponseEntity<ApiResponseDto<List<RoleDto>>> getAllRoles() {
        ApiResponseDto<List<RoleDto>> response = roleService.getAllRoles();
        return ResponseEntity.ok(response);
    }

    /**
     * Circuit breaker status endpoint for monitoring
     */
    @GetMapping("/circuit-breaker/status")
    @Operation(
            summary = "Circuit breaker status",
            description = "Get current circuit breaker status for monitoring"
    )
    public ResponseEntity<Map<String, Object>> getCircuitBreakerStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("authService", authServiceCircuitBreaker.getCircuitBreakerState());
        status.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(status);
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }
}