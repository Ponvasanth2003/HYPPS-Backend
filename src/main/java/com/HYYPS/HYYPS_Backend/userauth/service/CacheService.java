package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.entity.User;
import com.HYYPS.HYYPS_Backend.userauth.utils.SecurityConstants;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class CacheService {

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    @Cacheable(value = "users", key = "#email")
    public User getCachedUser(String email) {
        try {
            String userKey = SecurityConstants.CACHE_USER + email;
            String userJson = redisTemplate.opsForValue().get(userKey);

            if (userJson != null) {
                return objectMapper.readValue(userJson, User.class);
            }
        } catch (Exception e) {
            log.error("Failed to retrieve user from cache: {}", email, e);
        }
        return null;
    }

    public void cacheUser(User user) {
        try {
            String userKey = SecurityConstants.CACHE_USER + user.getEmail();
            String userJson = objectMapper.writeValueAsString(user);
            redisTemplate.opsForValue().set(userKey, userJson, 30, TimeUnit.MINUTES);
            log.debug("User cached: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to cache user: {}", user.getEmail(), e);
        }
    }

    @CacheEvict(value = "users", key = "#email")
    public void evictUserCache(String email) {
        try {
            String userKey = SecurityConstants.CACHE_USER + email;
            redisTemplate.delete(userKey);
            log.debug("User cache evicted: {}", email);
        } catch (Exception e) {
            log.error("Failed to evict user cache: {}", email, e);
        }
    }

    @CacheEvict(value = "users", allEntries = true)
    public void evictAllUserCache() {
        log.debug("All user cache evicted");
    }

    public void cacheSessionData(String sessionKey, Object data, long ttlMinutes) {
        try {
            String dataJson = objectMapper.writeValueAsString(data);
            redisTemplate.opsForValue().set(sessionKey, dataJson, ttlMinutes, TimeUnit.MINUTES);
            log.debug("Session data cached with key: {}", sessionKey);
        } catch (Exception e) {
            log.error("Failed to cache session data: {}", sessionKey, e);
        }
    }

    public <T> T getSessionData(String sessionKey, Class<T> clazz) {
        try {
            String dataJson = redisTemplate.opsForValue().get(sessionKey);
            if (dataJson != null) {
                return objectMapper.readValue(dataJson, clazz);
            }
        } catch (Exception e) {
            log.error("Failed to retrieve session data: {}", sessionKey, e);
        }
        return null;
    }

    public void evictSessionData(String sessionKey) {
        redisTemplate.delete(sessionKey);
        log.debug("Session data evicted: {}", sessionKey);
    }
}