package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
@Schema(description = "Confirm email update with OTP")
public class ConfirmEmailUpdateRequestDto {

    @Schema(description = "New email address", example = "newemail@example.com", required = true)
    @NotBlank(message = "New email is required")
    @Email(message = "Please provide a valid email address")
    private String newEmail;

    @Schema(description = "6-digit OTP code", example = "123456", required = true)
    @NotBlank(message = "OTP is required")
    @Pattern(regexp = "^[0-9]{6}$", message = "OTP must be 6 digits")
    private String otp;
}