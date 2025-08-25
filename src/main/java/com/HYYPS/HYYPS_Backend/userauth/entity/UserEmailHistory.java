package com.HYYPS.HYYPS_Backend.userauth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_email_history",
        indexes = {@Index(name = "idx_email", columnList = "email")})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserEmailHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, length = 150)
    private String email;

    @Column(name = "used_from", nullable = false)
    private LocalDateTime usedFrom;

    @Column(name = "used_until")
    private LocalDateTime usedUntil;

    @Column(name = "is_current", nullable = false)
    private Boolean isCurrent = false;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
}