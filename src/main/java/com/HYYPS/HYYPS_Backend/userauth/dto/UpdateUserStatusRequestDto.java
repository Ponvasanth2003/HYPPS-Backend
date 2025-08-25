package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(description = "Update user status request")
public class UpdateUserStatusRequestDto {

    @Schema(description = "Active status", example = "false", required = true)
    @NotNull(message = "Active status is required")
    private Boolean isActive;

    @Schema(description = "Reason for status change", example = "Policy violation")
    private String reason;
}