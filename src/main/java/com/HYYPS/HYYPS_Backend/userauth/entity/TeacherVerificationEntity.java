package com.HYYPS.HYYPS_Backend.userauth.entity;

import com.HYYPS.HYYPS_Backend.userauth.enums.SubmissionType;
import com.HYYPS.HYYPS_Backend.userauth.enums.VerificationStatus;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "teacher_verifications")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TeacherVerificationEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "submission_type", nullable = false)
    private SubmissionType submissionType;

    @Column(name = "file_url", nullable = false, length = 500)
    private String fileUrl;

    @Enumerated(EnumType.STRING)
    @Column(name = "profile_verification_status", nullable = false)
    private VerificationStatus profileVerificationStatus = VerificationStatus.PENDING;

    @Column(name = "rejection_reason", columnDefinition = "TEXT")
    private String rejectionReason;

    @Column(name = "verified_at")
    private LocalDateTime verifiedAt;

    @ManyToOne
    @JoinColumn(name = "verified_by")
    private User verifiedBy;

    @Column(name = "timer_started_at", nullable = false)
    private LocalDateTime timerStartedAt;

    @Column(name = "timer_expires_at", nullable = false)
    private LocalDateTime timerExpiresAt;

    @Column(name = "second_chance_allowed", nullable = false)
    private Boolean secondChanceAllowed = false;

    @Column(name = "retry_count", nullable = false)
    private Integer retryCount = 0;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}