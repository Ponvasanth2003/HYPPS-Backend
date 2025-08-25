package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Schema(description = "Create role request")
public class CreateRoleRequestDto {

    @Schema(description = "Role name", example = "MENTOR", required = true)
    @NotBlank(message = "Role name is required")
    @Size(min = 2, max = 50, message = "Role name must be between 2 and 50 characters")
    private String roleName;

    @Schema(description = "Role active status", example = "true")
    private Boolean isActive = true;
}