package com.HYYPS.HYYPS_Backend.userauth.utils;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class RateLimitUtil {

    private final RedisTemplate<String, String> redisTemplate;

    public boolean isRateLimited(String key, long windowSizeMinutes, int maxRequests) {
        String currentCount = redisTemplate.opsForValue().get(key);

        if (currentCount == null) {
            redisTemplate.opsForValue().set(key, "1", windowSizeMinutes, TimeUnit.MINUTES);
            return false;
        }

        int count = Integer.parseInt(currentCount);
        if (count >= maxRequests) {
            return true;
        }

        redisTemplate.opsForValue().increment(key);
        return false;
    }
}
