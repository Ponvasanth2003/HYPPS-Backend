//package com.HYYPS.HYYPS_Backend.userauth.config;
//
//import org.springframework.cache.CacheManager;
//import org.springframework.cache.annotation.EnableCaching;
//import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Primary;
//import org.springframework.data.redis.cache.RedisCacheConfiguration;
//import org.springframework.data.redis.cache.RedisCacheManager;
//import org.springframework.data.redis.connection.RedisConnectionFactory;
//import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
//import org.springframework.data.redis.serializer.RedisSerializationContext;
//import org.springframework.data.redis.serializer.StringRedisSerializer;
//
//import java.time.Duration;
//import java.util.HashMap;
//import java.util.Map;
//
//@Configuration
//@EnableCaching
//public class CacheConfig {
//
//    @Bean
//    @Primary
//    public CacheManager cacheManager(RedisConnectionFactory redisConnectionFactory) {
//        RedisCacheConfiguration defaultCacheConfig = RedisCacheConfiguration.defaultCacheConfig()
//                .entryTtl(Duration.ofMinutes(30))
//                .serializeKeysWith(RedisSerializationContext.SerializationPair.fromSerializer(new StringRedisSerializer()))
//                .serializeValuesWith(RedisSerializationContext.SerializationPair.fromSerializer(new GenericJackson2JsonRedisSerializer()))
//                .disableCachingNullValues();
//
//        Map<String, RedisCacheConfiguration> cacheConfigurations = new HashMap<>();
//
//        // User cache - 30 minutes
//        cacheConfigurations.put("users", defaultCacheConfig.entryTtl(Duration.ofMinutes(30)));
//
//        // Roles cache - 2 hours (roles don't change frequently)
//        cacheConfigurations.put("roles", defaultCacheConfig.entryTtl(Duration.ofHours(2)));
//
//        // OTP cache - 10 minutes
//        cacheConfigurations.put("otp", defaultCacheConfig.entryTtl(Duration.ofMinutes(10)));
//
//        // Session cache - 1 hour
//        cacheConfigurations.put("sessions", defaultCacheConfig.entryTtl(Duration.ofHours(1)));
//
//        return RedisCacheManager.builder(redisConnectionFactory)
//                .cacheDefaults(defaultCacheConfig)
//                .withInitialCacheConfigurations(cacheConfigurations)
//                .build();
//    }
//
//    @Bean
//    public CacheManager fallbackCacheManager() {
//        // Fallback to in-memory cache if Redis is unavailable
//        return new ConcurrentMapCacheManager("users", "roles", "otp", "sessions");
//    }
//}