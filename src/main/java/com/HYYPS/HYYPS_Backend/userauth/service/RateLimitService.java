package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.exception.RateLimitExceededException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class RateLimitService {

    private final RedisTemplate<String, String> redisTemplate;

    public boolean isRateLimited(String key, long windowMinutes, int maxRequests) {
        try {
            String rateLimitKey = "rate_limit:" + key;
            String currentCount = redisTemplate.opsForValue().get(rateLimitKey);

            if (currentCount == null) {
                // First request in window
                redisTemplate.opsForValue().set(rateLimitKey, "1", windowMinutes, TimeUnit.MINUTES);
                return false;
            }

            int count = Integer.parseInt(currentCount);
            if (count >= maxRequests) {
                log.warn("Rate limit exceeded for key: {}, count: {}, max: {}", key, count, maxRequests);
                return true;
            }

            // Increment counter
            redisTemplate.opsForValue().increment(rateLimitKey);
            return false;

        } catch (Exception e) {
            log.error("Error checking rate limit for key: {}", key, e);
            // In case of Redis error, allow the request to prevent service disruption
            return false;
        }
    }

    public void checkRateLimit(String key, long windowMinutes, int maxRequests, String errorMessage) {
        if (isRateLimited(key, windowMinutes, maxRequests)) {
            throw new RateLimitExceededException(errorMessage);
        }
    }

    public long getRemainingRequests(String key, int maxRequests) {
        try {
            String rateLimitKey = "rate_limit:" + key;
            String currentCount = redisTemplate.opsForValue().get(rateLimitKey);

            if (currentCount == null) {
                return maxRequests;
            }

            int count = Integer.parseInt(currentCount);
            return Math.max(0, maxRequests - count);

        } catch (Exception e) {
            log.error("Error getting remaining requests for key: {}", key, e);
            return maxRequests;
        }
    }

    public long getResetTime(String key) {
        try {
            String rateLimitKey = "rate_limit:" + key;
            return redisTemplate.getExpire(rateLimitKey, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.error("Error getting reset time for key: {}", key, e);
            return 0;
        }
    }

    public void resetRateLimit(String key) {
        try {
            String rateLimitKey = "rate_limit:" + key;
            redisTemplate.delete(rateLimitKey);
            log.debug("Rate limit reset for key: {}", key);
        } catch (Exception e) {
            log.error("Error resetting rate limit for key: {}", key, e);
        }
    }

    public boolean isIpSuspicious(String ip, int suspiciousThreshold, long windowHours) {
        try {
            String suspiciousKey = "suspicious_ip:" + ip;
            String count = redisTemplate.opsForValue().get(suspiciousKey);

            if (count == null) {
                return false;
            }

            return Integer.parseInt(count) >= suspiciousThreshold;

        } catch (Exception e) {
            log.error("Error checking suspicious IP: {}", ip, e);
            return false;
        }
    }

    public void markSuspiciousActivity(String ip) {
        try {
            String suspiciousKey = "suspicious_ip:" + ip;
            redisTemplate.opsForValue().increment(suspiciousKey);
            redisTemplate.expire(suspiciousKey, 24, TimeUnit.HOURS); // Reset daily
        } catch (Exception e) {
            log.error("Error marking suspicious activity for IP: {}", ip, e);
        }
    }
}