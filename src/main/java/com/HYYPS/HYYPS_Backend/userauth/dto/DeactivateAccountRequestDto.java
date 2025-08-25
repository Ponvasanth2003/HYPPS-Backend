package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Deactivate account request")
public class DeactivateAccountRequestDto {

    @Schema(description = "Current password for verification", example = "currentPassword123", required = true)
    @NotBlank(message = "Password is required")
    private String password;

    @Schema(description = "Reason for deactivation", example = "No longer needed")
    private String reason;
}