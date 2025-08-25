package com.HYYPS.HYYPS_Backend.userauth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "security_events")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_type", nullable = false, length = 100)
    private String eventType;

    @Column(name = "user_email", length = 150)
    private String userEmail;

    @Column(name = "client_ip", length = 45)
    private String clientIp;

    @Column(name = "details", length = 1000)
    private String details;

    @CreationTimestamp
    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;

    @Column(name = "severity", length = 20)
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "session_id", length = 100)
    private String sessionId;
}