package com.HYYPS.HYYPS_Backend.userauth.exception;

import com.HYYPS.HYYPS_Backend.userauth.dto.ApiResponseDto;
import com.HYYPS.HYYPS_Backend.userauth.security.SecurityEventLogger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final SecurityEventLogger securityEventLogger;

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleEmailAlreadyExists(EmailAlreadyExistsException ex, WebRequest request) {
        log.error("Email already exists: {}", ex.getMessage());
        securityEventLogger.logSecurityEvent("EMAIL_ALREADY_EXISTS", ex.getMessage(), getClientIp(request));
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(ApiResponseDto.error(ex.getMessage()));
    }

    @ExceptionHandler(InvalidOtpException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleInvalidOtp(InvalidOtpException ex, WebRequest request) {
        log.error("Invalid OTP: {}", ex.getMessage());
        securityEventLogger.logSecurityEvent("INVALID_OTP", "OTP verification failed", getClientIp(request));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponseDto.error(ex.getMessage()));
    }

    @ExceptionHandler(OtpExpiredException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleOtpExpired(OtpExpiredException ex, WebRequest request) {
        log.error("OTP expired: {}", ex.getMessage());
        securityEventLogger.logSecurityEvent("OTP_EXPIRED", "OTP expired", getClientIp(request));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponseDto.error(ex.getMessage()));
    }

    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleRateLimitExceeded(RateLimitExceededException ex, WebRequest request) {
        log.error("Rate limit exceeded: {}", ex.getMessage());
        securityEventLogger.logSecurityEvent("RATE_LIMIT_EXCEEDED", ex.getMessage(), getClientIp(request));
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(ApiResponseDto.error(ex.getMessage()));
    }

    @ExceptionHandler(VerificationException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleVerificationException(VerificationException ex, WebRequest request) {
        log.error("Verification error: {}", ex.getMessage());
        securityEventLogger.logSecurityEvent("VERIFICATION_ERROR", ex.getMessage(), getClientIp(request));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponseDto.error(ex.getMessage()));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleAuthenticationException(AuthenticationException ex, WebRequest request) {
        log.error("Authentication failed: {}", ex.getMessage());
        securityEventLogger.logSecurityEvent("AUTHENTICATION_FAILED", ex.getMessage(), getClientIp(request));
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponseDto.error("Authentication failed"));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleBadCredentials(BadCredentialsException ex, WebRequest request) {
        log.error("Bad credentials: {}", ex.getMessage());
        securityEventLogger.logSecurityEvent("BAD_CREDENTIALS", "Invalid credentials provided", getClientIp(request));
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponseDto.error("Invalid credentials"));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleAccessDenied(AccessDeniedException ex, WebRequest request) {
        log.error("Access denied: {}", ex.getMessage());
        securityEventLogger.logSecurityEvent("ACCESS_DENIED", ex.getMessage(), getClientIp(request));
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ApiResponseDto.error("Access denied"));
    }

    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleSecurityException(SecurityException ex, WebRequest request) {
        log.error("Security exception: {}", ex.getMessage());
        securityEventLogger.logSecurityEvent("SECURITY_EXCEPTION", ex.getMessage(), getClientIp(request));
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ApiResponseDto.error("Security violation"));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponseDto<Map<String, String>>> handleValidationErrors(
            MethodArgumentNotValidException ex, WebRequest request) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        log.error("Validation errors: {}", errors);
        securityEventLogger.logSecurityEvent("VALIDATION_ERROR", "Validation failed", getClientIp(request));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponseDto.error("Validation failed"));
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleRuntimeException(RuntimeException ex, WebRequest request) {
        log.error("Runtime exception: ", ex);
        securityEventLogger.logSecurityEvent("RUNTIME_EXCEPTION", ex.getMessage(), getClientIp(request));
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponseDto.error(ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponseDto<Void>> handleGenericException(Exception ex, WebRequest request) {
        log.error("Unexpected error: ", ex);
        securityEventLogger.logSecurityEvent("UNEXPECTED_ERROR", ex.getMessage(), getClientIp(request));
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponseDto.error("An unexpected error occurred"));
    }

    private String getClientIp(WebRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        // 🟢 Correct way to get RemoteAddr from HTTP Servlet Request:
        if (request instanceof org.springframework.web.context.request.ServletWebRequest servletWebRequest) {
            return servletWebRequest.getRequest().getRemoteAddr();
        }
        return "UNKNOWN"; // if all fails
    }
}