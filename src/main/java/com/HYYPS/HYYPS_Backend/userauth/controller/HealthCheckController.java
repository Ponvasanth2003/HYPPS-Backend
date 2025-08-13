package com.HYYPS.HYYPS_Backend.userauth.controller;

import com.HYYPS.HYYPS_Backend.userauth.dto.ApiResponseDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import javax.sql.DataSource;
import java.sql.Connection;
import java.util.HashMap;
import java.util.Map;

/**
 * Enhanced Health Check Controller for Production Monitoring
 *
 * WHY USE DETAILED HEALTH CHECKS?
 * 1. PROACTIVE MONITORING: Detect issues before users experience them
 * 2. LOAD BALANCER INTEGRATION: Help load balancers route traffic to healthy instances
 * 3. ALERTING: Trigger alerts when critical services are down
 * 4. DEBUGGING: Quickly identify which component is causing issues
 * 5. SLA COMPLIANCE: Meet uptime requirements by monitoring dependencies
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "health-monitoring", description = "System Health and Monitoring APIs")
public class HealthCheckController {

    @Autowired(required = false)
    private DataSource dataSource;

    @Autowired(required = false)
    private RedisConnectionFactory redisConnectionFactory;

    @Autowired(required = false)
    private KafkaTemplate<String, String> kafkaTemplate;

    /**
     * Basic health check - lightweight for load balancer
     *
     * USAGE: Load balancers call this every few seconds
     * RESPONSE TIME: Should be < 100ms
     */
    @GetMapping("/health")
    @Operation(
            summary = "Basic health check",
            description = "Lightweight health check for load balancers and quick status verification"
    )
    @ApiResponse(responseCode = "200", description = "Service is healthy")
    public ResponseEntity<ApiResponseDto<String>> health() {
        return ResponseEntity.ok(ApiResponseDto.success("Service is running", "OK"));
    }

    /**
     * Detailed health check with dependency status
     *
     * USAGE:
     * - Monitoring systems (Prometheus, New Relic, DataDog)
     * - DevOps dashboards
     * - Troubleshooting by support teams
     *
     * RESPONSE TIME: Can be 1-3 seconds (checks all dependencies)
     */
    @GetMapping("/health/detailed")
    @Operation(
            summary = "Detailed health check",
            description = "Comprehensive health check including all system dependencies (database, Redis, Kafka)"
    )
    public ResponseEntity<Map<String, Object>> detailedHealth() {
        Map<String, Object> health = new HashMap<>();
        Map<String, String> components = new HashMap<>();
        boolean overallHealthy = true;

        long startTime = System.currentTimeMillis();

        // Check Database Health
        try {
            String dbStatus = checkDatabaseHealth();
            components.put("database", dbStatus);
            if (!"UP".equals(dbStatus)) {
                overallHealthy = false;
            }
        } catch (Exception e) {
            components.put("database", "DOWN - " + e.getMessage());
            overallHealthy = false;
            log.error("Database health check failed", e);
        }

        // Check Redis Health
        try {
            String redisStatus = checkRedisHealth();
            components.put("redis", redisStatus);
            if (!"UP".equals(redisStatus)) {
                overallHealthy = false;
            }
        } catch (Exception e) {
            components.put("redis", "DOWN - " + e.getMessage());
            overallHealthy = false;
            log.error("Redis health check failed", e);
        }

        // Check Kafka Health
        try {
            String kafkaStatus = checkKafkaHealth();
            components.put("kafka", kafkaStatus);
            if (!"UP".equals(kafkaStatus)) {
                overallHealthy = false;
            }
        } catch (Exception e) {
            components.put("kafka", "DOWN - " + e.getMessage());
            overallHealthy = false;
            log.error("Kafka health check failed", e);
        }

        long endTime = System.currentTimeMillis();

        // Build response
        health.put("status", overallHealthy ? "UP" : "DOWN");
        health.put("components", components);
        health.put("timestamp", System.currentTimeMillis());
        health.put("responseTime", (endTime - startTime) + "ms");
        health.put("service", "HYYPS-Authentication");
        health.put("version", "1.0.0"); // Add your app version

        // Return appropriate HTTP status
        if (overallHealthy) {
            return ResponseEntity.ok(health);
        } else {
            return ResponseEntity.status(503).body(health); // Service Unavailable
        }
    }

    /**
     * Readiness probe for Kubernetes
     *
     * KUBERNETES USAGE:
     * - Determines if pod is ready to receive traffic
     * - Checks if all dependencies are available
     */
    @GetMapping("/health/ready")
    @Operation(
            summary = "Readiness probe",
            description = "Kubernetes readiness probe - checks if service is ready to handle requests"
    )
    public ResponseEntity<Map<String, Object>> readiness() {
        Map<String, Object> readiness = new HashMap<>();
        boolean ready = true;

        // Check critical dependencies only
        try {
            if (!"UP".equals(checkDatabaseHealth())) {
                ready = false;
            }
            if (!"UP".equals(checkRedisHealth())) {
                ready = false;
            }
        } catch (Exception e) {
            ready = false;
            log.error("Readiness check failed", e);
        }

        readiness.put("status", ready ? "UP" : "DOWN");
        readiness.put("timestamp", System.currentTimeMillis());

        return ready ? ResponseEntity.ok(readiness) : ResponseEntity.status(503).body(readiness);
    }

    /**
     * Liveness probe for Kubernetes
     *
     * KUBERNETES USAGE:
     * - Determines if pod should be restarted
     * - Simple check that application is not deadlocked
     */
    @GetMapping("/health/live")
    @Operation(
            summary = "Liveness probe",
            description = "Kubernetes liveness probe - simple check that application is running"
    )
    public ResponseEntity<Map<String, Object>> liveness() {
        Map<String, Object> liveness = new HashMap<>();
        liveness.put("status", "UP");
        liveness.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(liveness);
    }

    /**
     * Database Health Check
     *
     * WHAT IT CHECKS:
     * - Connection pool availability
     * - Database connectivity
     * - Basic query execution
     */
    private String checkDatabaseHealth() {
        if (dataSource == null) {
            return "NOT_CONFIGURED";
        }

        try (Connection connection = dataSource.getConnection()) {
            // Execute a simple query to verify database is responding
            if (connection.isValid(5)) { // 5 second timeout
                return "UP";
            } else {
                return "DOWN";
            }
        } catch (Exception e) {
            log.error("Database health check failed: {}", e.getMessage());
            return "DOWN";
        }
    }

    /**
     * Redis Health Check
     *
     * WHAT IT CHECKS:
     * - Redis connection availability
     * - Basic ping/pong test
     * - Connection pool status
     */
    private String checkRedisHealth() {
        if (redisConnectionFactory == null) {
            return "NOT_CONFIGURED";
        }

        try (RedisConnection connection = redisConnectionFactory.getConnection()) {
            // Execute ping command
            String pong = connection.ping();
            if ("PONG".equals(pong)) {
                return "UP";
            } else {
                return "DOWN";
            }
        } catch (Exception e) {
            log.error("Redis health check failed: {}", e.getMessage());
            return "DOWN";
        }
    }

    /**
     * Kafka Health Check
     *
     * WHAT IT CHECKS:
     * - Kafka broker connectivity
     * - Producer availability
     * - Basic metadata retrieval
     */
    private String checkKafkaHealth() {
        if (kafkaTemplate == null) {
            return "NOT_CONFIGURED";
        }

        try {
            // Try to get metadata - this will fail if Kafka is down
            kafkaTemplate.getProducerFactory().createProducer().partitionsFor("health-check-topic");
            return "UP";
        } catch (Exception e) {
            // It's normal for health-check-topic to not exist, but connection should work
            if (e.getMessage().contains("UnknownTopicOrPartitionException")) {
                return "UP"; // Kafka is up, topic just doesn't exist
            }
            log.error("Kafka health check failed: {}", e.getMessage());
            return "DOWN";
        }
    }
}

/**
 * PRODUCTION DEPLOYMENT GUIDE:
 *
 * 1. LOAD BALANCER CONFIGURATION:
 *    - Health Check URL: /api/auth/health
 *    - Check Interval: 10 seconds
 *    - Timeout: 5 seconds
 *    - Unhealthy Threshold: 3 consecutive failures
 *
 * 2. KUBERNETES CONFIGURATION:
 *    livenessProbe:
 *      httpGet:
 *        path: /api/auth/health/live
 *        port: 8080
 *      initialDelaySeconds: 30
 *      periodSeconds: 10
 *
 *    readinessProbe:
 *      httpGet:
 *        path: /api/auth/health/ready
 *        port: 8080
 *      initialDelaySeconds: 5
 *      periodSeconds: 5
 *
 * 3. MONITORING INTEGRATION:
 *    - Prometheus: Scrape /actuator/prometheus
 *    - Custom Alerts: Monitor /api/auth/health/detailed
 *    - Dashboard: Create graphs for response times and component status
 *
 * 4. ALERTING RULES:
 *    - Alert when overall status is DOWN for > 2 minutes
 *    - Alert when database is DOWN for > 30 seconds
 *    - Alert when Redis is DOWN (warning level)
 *    - Alert when response time > 5 seconds
 */