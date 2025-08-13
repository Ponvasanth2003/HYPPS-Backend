package com.HYYPS.HYYPS_Backend.userauth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "onboarding_data")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OnboardingEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne
    @JoinColumn(name = "role_id", nullable = false)
    private RoleEntity role;

    @Column(name = "profile_photo")
    private String profilePhoto;

    @Column(name = "full_name")
    private String fullName;

    @Column(name = "bio", columnDefinition = "TEXT")
    private String bio;

    @Column(name = "subject")
    private String subject;

    @Column(name = "interested_subjects")
    private String interestedSubjects;

    @Column(name = "teaching_level")
    private String teachingLevel;

    @Column(name = "learning_preference")
    private String learningPreference;

    @Column(name = "has_certificate")
    private Boolean hasCertificate;

//    @Column(name = "certificate_url")
//    private String certificateUrl;               ---- bending for AWS

    @Column(name = "teaching_video_url")
    private String teachingVideoUrl;

    @Column(name = "class_type")
    private String classType;

    @Column(name = "preferred_learning_type")
    private String preferredLearningType;

    @Column(name = "free_class_amount")
    private Double freeClassAmount;

    @Column(name = "weekly_schedule", columnDefinition = "TEXT")
    private String weeklySchedule;

    @Column(name = "first_class_title")
    private String firstClassTitle;

    @Column(name = "first_class_description", columnDefinition = "TEXT")
    private String firstClassDescription;

    @Column(name = "course_duration_days")
    private Integer courseDurationDays;

    @Column(name = "batches_per_day")
    private Integer batchesPerDay;

    @Column(name = "batch_duration_minutes")
    private Integer batchDurationMinutes;

    @Column(name = "max_students_per_batch")
    private Integer maxStudentsPerBatch;

    @Column(name = "ready_to_start")
    private String readyToStart;

    @Column(name = "is_completed", nullable = false)
    private Boolean isCompleted = false;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}