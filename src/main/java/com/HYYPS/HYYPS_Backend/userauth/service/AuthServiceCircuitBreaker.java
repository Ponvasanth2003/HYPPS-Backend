package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.ApiResponseDto;
import com.HYYPS.HYYPS_Backend.userauth.dto.LoginRequestDto;
import com.HYYPS.HYYPS_Backend.userauth.dto.SocialLoginRequestDto;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import io.github.resilience4j.timelimiter.annotation.TimeLimiter;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Circuit Breaker wrapper for AuthService
 *
 * WHY USE CIRCUIT BREAKER?
 * 1. Prevents cascade failures when external services (DB, Redis, Kafka) are down
 * 2. Provides graceful degradation instead of complete system failure
 * 3. Automatically recovers when services are back online
 * 4. Improves user experience with meaningful error messages
 * 5. Protects system resources from being exhausted by failing operations
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuthServiceCircuitBreaker {

    private final AuthService authService;

    /**
     * Login with Circuit Breaker Protection
     *
     * PROTECTION LAYERS:
     * 1. CircuitBreaker: Opens circuit if 50% of calls fail in 100 requests
     * 2. Retry: Retries 3 times with exponential backoff
     * 3. TimeLimiter: Timeout after 5 seconds
     */
    @CircuitBreaker(name = "authService", fallbackMethod = "fallbackLogin")
    @Retry(name = "authService")
    @TimeLimiter(name = "authService")
    public CompletableFuture<ApiResponseDto<Map<String, Object>>> loginWithCircuitBreaker(
            LoginRequestDto request, HttpServletResponse httpResponse) {

        return CompletableFuture.supplyAsync(() -> {
            log.debug("Attempting login with circuit breaker protection for: {}", request.getEmail());
            return authService.login(request, httpResponse);
        });
    }

    /**
     * Social Login with Circuit Breaker Protection
     */
    @CircuitBreaker(name = "authService", fallbackMethod = "fallbackSocialLogin")
    @Retry(name = "authService")
    @TimeLimiter(name = "authService")
    public CompletableFuture<ApiResponseDto<Map<String, Object>>> socialLoginWithCircuitBreaker(
            SocialLoginRequestDto request, HttpServletResponse httpResponse) {

        return CompletableFuture.supplyAsync(() -> {
            log.debug("Attempting social login with circuit breaker protection for: {}", request.getEmail());
            return authService.socialLogin(request, httpResponse);
        });
    }

    /**
     * Fallback method for login when circuit is OPEN or service fails
     *
     * FALLBACK STRATEGY:
     * 1. Log the failure for monitoring
     * 2. Return user-friendly error message
     * 3. Don't expose internal error details
     * 4. Provide guidance for users
     */
    public CompletableFuture<ApiResponseDto<Map<String, Object>>> fallbackLogin(
            LoginRequestDto request, HttpServletResponse httpResponse, Exception ex) {

        log.error("Login service unavailable for email: {}, using fallback. Error: {}",
                request.getEmail(), ex.getMessage());

        // Determine fallback response based on exception type
        String errorMessage;
        if (ex instanceof java.util.concurrent.TimeoutException) {
            errorMessage = "Login is taking longer than expected. Please try again.";
        } else {
            errorMessage = "Authentication service is temporarily unavailable. Please try again in a few moments.";
        }

        return CompletableFuture.completedFuture(
                ApiResponseDto.error(errorMessage)
        );
    }

    /**
     * Fallback method for social login
     */
    public CompletableFuture<ApiResponseDto<Map<String, Object>>> fallbackSocialLogin(
            SocialLoginRequestDto request, HttpServletResponse httpResponse, Exception ex) {

        log.error("Social login service unavailable for email: {}, using fallback. Error: {}",
                request.getEmail(), ex.getMessage());

        String errorMessage = "Social authentication is temporarily unavailable. Please try regular login or try again later.";

        return CompletableFuture.completedFuture(
                ApiResponseDto.error(errorMessage)
        );
    }

    /**
     * Get circuit breaker state for monitoring
     */
    public String getCircuitBreakerState() {
        // This would require injecting CircuitBreakerRegistry if you need runtime state
        return "CLOSED"; // Placeholder - implement if needed
    }
}

/**
 * WHEN TO USE THIS COMPONENT:
 *
 * 1. HIGH-TRAFFIC PRODUCTION ENVIRONMENTS
 *    - When you have thousands of concurrent users
 *    - When system stability is critical
 *
 * 2. MICROSERVICES ARCHITECTURE
 *    - When auth service depends on multiple external services
 *    - When failures in one service shouldn't bring down the entire system
 *
 * 3. CLOUD DEPLOYMENTS
 *    - When using external databases, Redis clusters, message queues
 *    - When network partitions or service outages are possible
 *
 * HOW IT WORKS:
 *
 * CLOSED STATE (Normal Operation):
 * - All requests pass through normally
 * - Monitors success/failure rates
 *
 * OPEN STATE (Circuit Tripped):
 * - All requests immediately return fallback response
 * - No load on failing downstream services
 * - Allows services to recover
 *
 * HALF-OPEN STATE (Testing Recovery):
 * - Limited number of test requests allowed
 * - If successful, circuit closes
 * - If failed, circuit opens again
 */