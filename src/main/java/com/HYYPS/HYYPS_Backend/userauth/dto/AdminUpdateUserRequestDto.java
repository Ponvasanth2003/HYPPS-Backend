package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Schema(description = "Admin update user request")
public class AdminUpdateUserRequestDto {

    @Schema(description = "User's full name", example = "John Updated Doe")
    @Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
    private String name;

    @Schema(description = "User's email address", example = "updated@example.com")
    @Email(message = "Please provide a valid email address")
    private String email;

    @Schema(description = "Account active status", example = "true")
    private Boolean isActive;

    @Schema(description = "Email verification status", example = "true")
    private Boolean isEmailVerified;

    @Schema(description = "Phone number", example = "+1234567890")
    private String phoneNumber;

    @Schema(description = "Profile picture URL", example = "https://example.com/profile.jpg")
    private String profilePicture;
}