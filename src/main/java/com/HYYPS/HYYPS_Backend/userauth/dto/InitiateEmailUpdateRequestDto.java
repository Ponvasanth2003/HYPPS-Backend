package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Initiate email update request")
public class InitiateEmailUpdateRequestDto {

    @Schema(description = "New email address", example = "newemail@example.com", required = true)
    @NotBlank(message = "New email is required")
    @Email(message = "Please provide a valid email address")
    private String newEmail;

    @Schema(description = "Current password for verification", example = "currentPassword123", required = true)
    @NotBlank(message = "Password is required")
    private String password;
}