package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Schema(description = "Change password request")
public class ChangePasswordRequestDto {

    @Schema(description = "Current password", example = "currentPassword123", required = true)
    @NotBlank(message = "Current password is required")
    private String currentPassword;

    @Schema(description = "New password", example = "newSecurePassword123", required = true)
    @NotBlank(message = "New password is required")
    @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters")
    private String newPassword;

    @Schema(description = "Confirm new password", example = "newSecurePassword123", required = true)
    @NotBlank(message = "Confirm password is required")
    private String confirmPassword;
}