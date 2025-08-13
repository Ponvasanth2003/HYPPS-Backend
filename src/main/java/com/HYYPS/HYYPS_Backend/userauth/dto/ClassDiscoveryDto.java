package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.List;

@Data
@Schema(description = "Class discovery form request")
public class ClassDiscoveryDto {

    @Schema(description = "Interested subjects/tags", example = "[\"Mathematics\", \"Physics\"]", required = true)
    private List<String> interestedSubjects;

    @Schema(description = "Learning level", example = "BEGINNER", required = true)
    @NotBlank(message = "Learning level is required")
    private String learningLevel; // BEGINNER, INTERMEDIATE, ADVANCED

    @Schema(description = "Preferred learning type", example = "BOTH", required = true)
    @NotBlank(message = "Preferred learning type is required")
    private String preferredLearningType; // FREE, PAID, BOTH
}