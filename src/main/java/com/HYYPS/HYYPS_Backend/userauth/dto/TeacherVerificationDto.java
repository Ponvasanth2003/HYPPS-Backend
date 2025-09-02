package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(description = "Teacher verification details")
public class TeacherVerificationDto {

    @Schema(description = "Teacher verification ID")
    private Long id;

    @Schema(description = "User ID")
    private Long userId;

    @Schema(description = "Teacher name")
    private String teacherName;

    @Schema(description = "Teacher email")
    private String teacherEmail;

    @Schema(description = "Submission type", example = "CERTIFICATE")
    private String submissionType;

    @Schema(description = "File URL")
    private String fileUrl;

    @Schema(description = "Profile verification status", example = "PENDING")
    private String profileVerificationStatus;

    @Schema(description = "Rejection reason")
    private String rejectionReason;

    @Schema(description = "Verified at timestamp")
    private String verifiedAt;

    @Schema(description = "Verified by admin name")
    private String verifiedByName;

    @Schema(description = "Timer started at")
    private String timerStartedAt;

    @Schema(description = "Timer expires at")
    private String timerExpiresAt;

    @Schema(description = "Days remaining")
    private Long daysRemaining;

    @Schema(description = "Second chance allowed")
    private Boolean secondChanceAllowed;

    @Schema(description = "Retry count")
    private Integer retryCount;

    @Schema(description = "Created at")
    private String createdAt;
}