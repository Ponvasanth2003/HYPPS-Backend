package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(description = "Profile verification request")
public class ProfileVerificationRequestDto {

    @Schema(description = "Verification action", example = "VERIFY", allowableValues = {"VERIFY", "REJECT"})
    @NotBlank(message = "Action is required")
    private String action; // VERIFY or REJECT

    @Schema(description = "Rejection reason (required if action is REJECT)", example = "Certificate is not clear or invalid")
    private String rejectionReason;
}