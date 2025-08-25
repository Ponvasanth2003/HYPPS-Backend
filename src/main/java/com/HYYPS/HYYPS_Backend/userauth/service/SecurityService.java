package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.entity.SecurityEvent;
import com.HYYPS.HYYPS_Backend.userauth.repository.SecurityEventRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class SecurityService {

    private final SecurityEventRepository securityEventRepository;
    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ApiResponseDto<Map<String, Object>> getSecurityEvents(int page, int size, String eventType, String userEmail) {
        try {
            Pageable pageable = PageRequest.of(page, size, Sort.by("timestamp").descending());

            Page<SecurityEvent> eventPage;
            if (eventType != null && userEmail != null) {
                eventPage = securityEventRepository.findByEventTypeAndUserEmailContaining(eventType, userEmail, pageable);
            } else if (eventType != null) {
                eventPage = securityEventRepository.findByEventType(eventType, pageable);
            } else if (userEmail != null) {
                eventPage = securityEventRepository.findByUserEmailContaining(userEmail, pageable);
            } else {
                eventPage = securityEventRepository.findAll(pageable);
            }

            List<Map<String, Object>> events = eventPage.getContent().stream()
                    .map(this::createSecurityEventMap)
                    .collect(Collectors.toList());

            Map<String, Object> response = new HashMap<>();
            response.put("events", events);
            response.put("pagination", createPaginationMap(eventPage));

            return ApiResponseDto.success("Security events retrieved successfully", response);
        } catch (Exception e) {
            log.error("Failed to retrieve security events", e);
            return ApiResponseDto.error("Failed to retrieve security events");
        }
    }

    public ApiResponseDto<Map<String, Object>> getSuspiciousActivity() {
        try {
            // Get failed login attempts in last 24 hours
            LocalDateTime since = LocalDateTime.now().minusDays(1);
            List<SecurityEvent> failedLogins = securityEventRepository
                    .findByEventTypeAndTimestampAfter("LOGIN_FAILED", since);

            // Group by IP and email to identify patterns
            Map<String, Long> failedLoginsByIp = failedLogins.stream()
                    .collect(Collectors.groupingBy(SecurityEvent::getClientIp, Collectors.counting()));

            Map<String, Long> failedLoginsByEmail = failedLogins.stream()
                    .collect(Collectors.groupingBy(SecurityEvent::getUserEmail, Collectors.counting()));

            // Get rate limit violations
            Map<String, Long> rateLimitViolations = securityEventRepository
                    .findByEventTypeAndTimestampAfter("RATE_LIMIT_EXCEEDED", since)
                    .stream()
                    .collect(Collectors.groupingBy(SecurityEvent::getClientIp, Collectors.counting()));

            Map<String, Object> suspicious = new HashMap<>();
            suspicious.put("suspiciousIPs", failedLoginsByIp.entrySet().stream()
                    .filter(entry -> entry.getValue() > 5)
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));

            suspicious.put("suspiciousEmails", failedLoginsByEmail.entrySet().stream()
                    .filter(entry -> entry.getValue() > 3)
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));

            suspicious.put("rateLimitViolations", rateLimitViolations);
            suspicious.put("totalFailedLogins", failedLogins.size());
            suspicious.put("timeRange", "Last 24 hours");

            return ApiResponseDto.success("Suspicious activity retrieved successfully", suspicious);
        } catch (Exception e) {
            log.error("Failed to retrieve suspicious activity", e);
            return ApiResponseDto.error("Failed to retrieve suspicious activity");
        }
    }

    public ApiResponseDto<Void> blockIpAddress(BlockIpRequestDto request) {
        try {
            String blockKey = "blocked_ip:" + request.getIpAddress();

            Map<String, Object> blockInfo = new HashMap<>();
            blockInfo.put("reason", request.getReason());
            blockInfo.put("blockedAt", LocalDateTime.now().toString());
            blockInfo.put("durationHours", request.getDurationHours());
            blockInfo.put("ipAddress", request.getIpAddress());

            String blockInfoJson = objectMapper.writeValueAsString(blockInfo);
            redisTemplate.opsForValue().set(blockKey, blockInfoJson,
                    Duration.ofHours(request.getDurationHours()));

            log.info("IP address {} blocked for {} hours. Reason: {}",
                    request.getIpAddress(), request.getDurationHours(), request.getReason());

            return ApiResponseDto.success("IP address blocked successfully");
        } catch (Exception e) {
            log.error("Failed to block IP address: {}", request.getIpAddress(), e);
            return ApiResponseDto.error("Failed to block IP address");
        }
    }

    public ApiResponseDto<Void> unblockIpAddress(String ipAddress) {
        try {
            String blockKey = "blocked_ip:" + ipAddress;
            Boolean deleted = redisTemplate.delete(blockKey);

            if (Boolean.TRUE.equals(deleted)) {
                log.info("IP address {} unblocked successfully", ipAddress);
                return ApiResponseDto.success("IP address unblocked successfully");
            } else {
                return ApiResponseDto.error("IP address was not blocked or already expired");
            }
        } catch (Exception e) {
            log.error("Failed to unblock IP address: {}", ipAddress, e);
            return ApiResponseDto.error("Failed to unblock IP address");
        }
    }

    public ApiResponseDto<Map<String, Object>> getBlockedIps() {
        try {
            Set<String> blockedIpKeys = redisTemplate.keys("blocked_ip:*");
            List<Map<String, Object>> blockedIps = blockedIpKeys.stream()
                    .map(key -> {
                        try {
                            String ipAddress = key.replace("blocked_ip:", "");
                            String blockInfoJson = redisTemplate.opsForValue().get(key);
                            Long ttl = redisTemplate.getExpire(key);

                            Map<String, Object> ipInfo = new HashMap<>();
                            ipInfo.put("ipAddress", ipAddress);
                            ipInfo.put("ttlSeconds", ttl);

                            if (blockInfoJson != null) {
                                // Parse the JSON to get block details
                                Map<String, Object> blockInfo = objectMapper.readValue(blockInfoJson, Map.class);
                                ipInfo.putAll(blockInfo);
                            }

                            return ipInfo;
                        } catch (Exception e) {
                            log.error("Failed to parse blocked IP info for key: {}", key, e);
                            return null;
                        }
                    })
                    .filter(ipInfo -> ipInfo != null)
                    .collect(Collectors.toList());

            Map<String, Object> response = new HashMap<>();
            response.put("blockedIps", blockedIps);
            response.put("totalBlocked", blockedIps.size());

            return ApiResponseDto.success("Blocked IPs retrieved successfully", response);
        } catch (Exception e) {
            log.error("Failed to retrieve blocked IPs", e);
            return ApiResponseDto.error("Failed to retrieve blocked IPs");
        }
    }

    private Map<String, Object> createSecurityEventMap(SecurityEvent event) {
        Map<String, Object> eventMap = new HashMap<>();
        eventMap.put("id", event.getId());
        eventMap.put("eventType", event.getEventType());
        eventMap.put("userEmail", event.getUserEmail());
        eventMap.put("clientIp", event.getClientIp());
        eventMap.put("timestamp", event.getTimestamp());
        eventMap.put("details", event.getDetails());
        eventMap.put("severity", event.getSeverity());
        return eventMap;
    }

    private Map<String, Object> createPaginationMap(Page<?> page) {
        Map<String, Object> pagination = new HashMap<>();
        pagination.put("page", page.getNumber());
        pagination.put("size", page.getSize());
        pagination.put("totalElements", page.getTotalElements());
        pagination.put("totalPages", page.getTotalPages());
        pagination.put("isFirst", page.isFirst());
        pagination.put("isLast", page.isLast());

        return pagination;
    }
}