package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.OtpEventDto;
import com.HYYPS.HYYPS_Backend.userauth.exception.InvalidOtpException;
import com.HYYPS.HYYPS_Backend.userauth.exception.OtpExpiredException;
import com.HYYPS.HYYPS_Backend.userauth.exception.RateLimitExceededException;
import com.HYYPS.HYYPS_Backend.userauth.utils.OtpGenerator;
import com.HYYPS.HYYPS_Backend.userauth.security.SecurityEventLogger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class OtpService {

    private final RedisTemplate<String, String> redisTemplate;
    private final KafkaProducerService kafkaProducerService;
    private final SecurityEventLogger securityEventLogger;

    private static final String OTP_PREFIX = "otp:";
    private static final String RATE_LIMIT_PREFIX = "rate_limit:";
    private static final long OTP_EXPIRY_MINUTES = 10;
    private static final long RATE_LIMIT_MINUTES = 1;
    private static final int MAX_OTP_ATTEMPTS = 3;
    private static final String ATTEMPT_PREFIX = "otp_attempts:";

    /**
     * Generate OTP and publish Kafka event for async processing
     */
    public String generateAndPublishOtpEvent(String email, String name,
                                             OtpEventDto.OtpEventType eventType, String clientIp) {
        // Check rate limit
        String rateLimitKey = RATE_LIMIT_PREFIX + email;
        if (Boolean.TRUE.equals(redisTemplate.hasKey(rateLimitKey))) {
            throw new RateLimitExceededException("Please wait before requesting a new OTP");
        }

        // Generate OTP
        String otp = OtpGenerator.generate();

        // Create OTP event
        OtpEventDto otpEvent = OtpEventDto.builder()
                .eventType(eventType)
                .email(email)
                .name(name)
                .otp(otp)
                .clientIp(clientIp)
                .retryCount(0)
                .build();

        // Publish to Kafka for async processing
        kafkaProducerService.publishOtpEvent(otpEvent);

        // Set rate limit
        redisTemplate.opsForValue().set(rateLimitKey, "1", RATE_LIMIT_MINUTES, TimeUnit.MINUTES);

        // Reset attempt counter
        String attemptKey = ATTEMPT_PREFIX + email;
        redisTemplate.delete(attemptKey);

        log.info("OTP generation event published for email: {}", email);
        return otp;
    }

    /**
     * Store OTP in Redis (called by Kafka consumer after successful generation)
     */
    public void storeOtp(String email, String otp) {
        String otpKey = OTP_PREFIX + email;
        redisTemplate.opsForValue().set(otpKey, otp, OTP_EXPIRY_MINUTES, TimeUnit.MINUTES);
        log.debug("OTP stored in Redis for email: {}", email);
    }

    // Keep existing verification methods unchanged
    public void verifyOtp(String email, String inputOtp) {
        String otpKey = OTP_PREFIX + email;
        String storedOtp = redisTemplate.opsForValue().get(otpKey);

        if (storedOtp == null) {
            throw new OtpExpiredException("OTP has expired or does not exist");
        }

        // Check attempt count to prevent brute force
        String attemptKey = ATTEMPT_PREFIX + email;
        String attemptCount = redisTemplate.opsForValue().get(attemptKey);
        int attempts = attemptCount != null ? Integer.parseInt(attemptCount) : 0;

        if (attempts >= MAX_OTP_ATTEMPTS) {
            redisTemplate.delete(otpKey);
            throw new InvalidOtpException("Maximum OTP attempts exceeded. Please request a new OTP.");
        }

        if (!storedOtp.equals(inputOtp)) {
            redisTemplate.opsForValue().set(attemptKey, String.valueOf(attempts + 1),
                    OTP_EXPIRY_MINUTES, TimeUnit.MINUTES);
            throw new InvalidOtpException("Invalid OTP. Attempts remaining: " + (MAX_OTP_ATTEMPTS - attempts - 1));
        }

        // OTP is valid, clean up all related keys
        redisTemplate.delete(otpKey);
        redisTemplate.delete(attemptKey);
        log.info("OTP verified and deleted for email: {}", email);
    }

    // Keep other existing methods unchanged
    public void deleteOtp(String email) {
        String otpKey = OTP_PREFIX + email;
        String attemptKey = ATTEMPT_PREFIX + email;
        redisTemplate.delete(otpKey);
        redisTemplate.delete(attemptKey);
        log.info("OTP and related data deleted for email: {}", email);
    }

    public boolean isOtpValid(String email) {
        String otpKey = OTP_PREFIX + email;
        return Boolean.TRUE.equals(redisTemplate.hasKey(otpKey));
    }

    public long getOtpRemainingTime(String email) {
        String otpKey = OTP_PREFIX + email;
        return redisTemplate.getExpire(otpKey, TimeUnit.SECONDS);
    }
}