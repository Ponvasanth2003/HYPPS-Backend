package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Role information")
public class RoleDto {

    @Schema(description = "Role ID", example = "1")
    private Long roleId;

    @Schema(description = "Role name", example = "STUDENT")
    private String roleName;

    @Schema(description = "Onboarding completion status", example = "true")
    private Boolean isOnboarded;
}