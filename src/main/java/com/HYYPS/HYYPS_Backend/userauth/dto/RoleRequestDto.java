package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Schema(description = "Role assignment request")
public class RoleRequestDto {

    @Schema(description = "Role ID to assign", example = "1", required = true)
    @NotNull(message = "Role ID is required")
    private Long roleId;
}