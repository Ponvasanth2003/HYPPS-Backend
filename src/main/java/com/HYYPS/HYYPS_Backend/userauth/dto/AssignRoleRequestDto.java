package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(description = "Assign role to user request")
public class AssignRoleRequestDto {

    @Schema(description = "Role ID to assign", example = "2", required = true)
    @NotNull(message = "Role ID is required")
    private Long roleId;

    @Schema(description = "Onboarding completion status", example = "false")
    private Boolean isOnboarded = false;
}