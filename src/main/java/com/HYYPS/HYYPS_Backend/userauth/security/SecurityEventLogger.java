package com.HYYPS.HYYPS_Backend.userauth.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityEventLogger {

    private final RedisTemplate<String, String> redisTemplate;
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public void logSecurityEvent(String eventType, String userIdentifier, String clientIp) {
        String timestamp = LocalDateTime.now().format(FORMATTER);
        String logEntry = String.format("[%s] %s - User: %s, IP: %s",
                timestamp, eventType, userIdentifier, clientIp);

        // Log to application logs
        log.info("SECURITY_EVENT: {}", logEntry);

        // Store in Redis for monitoring (keep for 30 days)
        String redisKey = "security_events:" + eventType + ":" + System.currentTimeMillis();
        redisTemplate.opsForValue().set(redisKey, logEntry, 30, TimeUnit.DAYS);

        // Store user-specific events (keep for 7 days)
        if (userIdentifier != null && !userIdentifier.isEmpty()) {
            String userKey = "user_security_events:" + userIdentifier;
            redisTemplate.opsForList().leftPush(userKey, logEntry);
            redisTemplate.expire(userKey, 7, TimeUnit.DAYS);

            // Keep only last 100 events per user
            redisTemplate.opsForList().trim(userKey, 0, 99);
        }

        // Store IP-specific events for suspicious activity monitoring
        if (clientIp != null && !clientIp.isEmpty()) {
            String ipKey = "ip_security_events:" + clientIp;
            redisTemplate.opsForList().leftPush(ipKey, logEntry);
            redisTemplate.expire(ipKey, 1, TimeUnit.DAYS);

            // Keep only last 50 events per IP
            redisTemplate.opsForList().trim(ipKey, 0, 49);
        }
    }

    public void logFailedLoginAttempt(String email, String clientIp) {
        logSecurityEvent("FAILED_LOGIN_ATTEMPT", email, clientIp);

        // Track consecutive failed attempts
        String failedAttemptsKey = "failed_login_attempts:" + email;
        redisTemplate.opsForValue().increment(failedAttemptsKey);
        redisTemplate.expire(failedAttemptsKey, 30, TimeUnit.MINUTES);
    }

    public void logSuccessfulLogin(String email, String clientIp) {
        logSecurityEvent("SUCCESSFUL_LOGIN", email, clientIp);

        // Clear failed attempts on successful login
        String failedAttemptsKey = "failed_login_attempts:" + email;
        redisTemplate.delete(failedAttemptsKey);
    }

    public void logSuspiciousActivity(String eventType, String userIdentifier, String clientIp, String details) {
        String suspiciousLogEntry = String.format("SUSPICIOUS_ACTIVITY - %s: %s", eventType, details);
        logSecurityEvent(suspiciousLogEntry, userIdentifier, clientIp);

        // Store in high-priority suspicious events
        String suspiciousKey = "suspicious_events:" + System.currentTimeMillis();
        redisTemplate.opsForValue().set(suspiciousKey, suspiciousLogEntry, 90, TimeUnit.DAYS);
    }

    public long getFailedLoginAttempts(String email) {
        String failedAttemptsKey = "failed_login_attempts:" + email;
        String attempts = redisTemplate.opsForValue().get(failedAttemptsKey);
        return attempts != null ? Long.parseLong(attempts) : 0;
    }
}