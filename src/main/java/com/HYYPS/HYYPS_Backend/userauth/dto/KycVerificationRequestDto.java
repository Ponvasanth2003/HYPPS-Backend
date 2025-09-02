package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "KYC verification request")
public class KycVerificationRequestDto {

    @Schema(description = "Verification action", example = "VERIFY", allowableValues = {"VERIFY", "REJECT"})
    @NotBlank(message = "Action is required")
    private String action; // VERIFY or REJECT

    @Schema(description = "Rejection reason (required if action is REJECT)")
    private String rejectionReason;
}