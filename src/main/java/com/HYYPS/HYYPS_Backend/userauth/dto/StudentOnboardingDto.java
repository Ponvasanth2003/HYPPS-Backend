package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import java.util.List;
import jakarta.validation.constraints.NotEmpty;

@Data
@Schema(description = "Student onboarding request")
public class StudentOnboardingDto {

    @Schema(description = "Profile photo URL (optional)", example = "https://s3.amazonaws.com/photos/profile.jpg")
    private String profilePhoto;

    @Schema(description = "Student's full name", example = "Jane Doe", required = true)
    @NotBlank(message = "Name is required")
    private String name;

    @Schema(description = "Interested subjects", example = "Mathematics, Physics", required = true)
    @NotEmpty(message = "Interested subjects are required")
    private List<String> interestedSubjects;

    @Schema(description = "Learning preference level", example = "BEGINNER", required = true)
    @NotBlank(message = "Learning preference is required")
    private String learningPreference; // BEGINNER, INTERMEDIATE, ADVANCED

    @Schema(description = "Preferred learning type", example = "BOTH", required = true)
    @NotBlank(message = "Preferred learning type is required")
    private String preferredLearningType; // FREE, PAID, BOTH

    @Schema(description = "Ready to start learning option", example = "FIND_CLASSES", required = true)
    @NotBlank(message = "Ready to start option is required")
    private String readyToStart; // FIND_CLASSES, DASHBOARD

    @Schema(description = "Complete setup flag", example = "true")
    private Boolean completeSetup = false;
}
