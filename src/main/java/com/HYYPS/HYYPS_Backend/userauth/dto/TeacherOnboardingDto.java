package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(description = "Teacher onboarding request")
public class TeacherOnboardingDto {

    @Schema(description = "Profile photo URL (optional)", example = "https://s3.amazonaws.com/photos/profile.jpg")
    private String profilePhoto;

    @Schema(description = "Teacher's full name", example = "John Smith", required = true)
    @NotBlank(message = "Name is required")
    private String name;

    @Schema(description = "Teacher's bio/description", example = "Experienced mathematics teacher with 10+ years", required = true)
    @NotBlank(message = "Bio is required")
    private String bio;

    @Schema(description = "Subject teaching", example = "Mathematics", required = true)
    @NotBlank(message = "Subject is required")
    private String subject;

    @Schema(description = "Teaching level", example = "INTERMEDIATE", required = true)
    @NotBlank(message = "Teaching level is required")
    private String teachingLevel; // BEGINNER, INTERMEDIATE, ADVANCED

    @Schema(description = "Has certificate", example = "true", required = true)
    @NotNull(message = "Certificate status is required")
    private Boolean hasCertificate;

    @Schema(description = "Certificate file URL (if hasCertificate is true)", example = "https://s3.amazonaws.com/certificates/cert.pdf")
    private String certificateUrl;

    @Schema(description = "Teaching video URL (if hasCertificate is false)", example = "https://s3.amazonaws.com/videos/teaching.mp4")
    private String teachingVideoUrl;

    @Schema(description = "Class type preference", example = "BOTH", required = true)
    @NotBlank(message = "Class type is required")
    private String classType; // FREE, PAID, BOTH

    @Schema(description = "Amount for free classes (if classType includes FREE)", example = "2000")
    private Double freeClassAmount;

    @Schema(description = "Weekly schedule availability (optional)", example = "Monday: 9AM-5PM, Tuesday: 10AM-6PM")
    private String weeklySchedule;

    @Schema(description = "First class title (optional)", example = "Introduction to Algebra")
    private String firstClassTitle;

    @Schema(description = "First class description (optional)", example = "Basic concepts of algebra for beginners")
    private String firstClassDescription;

    @Schema(description = "Course duration in days (optional)", example = "30")
    private Integer courseDurationDays;

    @Schema(description = "Batches per day (optional)", example = "2")
    private Integer batchesPerDay;

    @Schema(description = "Duration per batch in minutes (optional)", example = "60")
    private Integer batchDurationMinutes;

    @Schema(description = "Maximum students per batch (optional)", example = "20")
    private Integer maxStudentsPerBatch;

    @Schema(description = "Complete setup flag", example = "true")
    private Boolean completeSetup = false;
}