package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Schema(description = "Update profile request")
public class UpdateProfileRequestDto {

    @Schema(description = "User's full name", example = "John Updated Doe")
    @Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
    private String name;

    @Schema(description = "Phone number with country code", example = "+1234567890")
    @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$", message = "Please provide a valid phone number")
    private String phoneNumber;

    @Schema(description = "Date of birth in YYYY-MM-DD format", example = "1990-01-01")
    private String dateOfBirth;

    @Schema(description = "Profile picture URL", example = "https://example.com/profile.jpg")
    private String profilePicture;
}