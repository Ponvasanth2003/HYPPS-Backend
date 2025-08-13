package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Social login request")
public class SocialLoginRequestDto {

    @Schema(description = "Social provider token", example = "google_token_here", required = true)
    @NotBlank(message = "Token is required")
    private String token;

    @Schema(description = "Social provider", example = "GOOGLE", required = true)
    @NotBlank(message = "Provider is required")
    private String provider; // GOOGLE, FACEBOOK

    @Schema(description = "User's email from social provider", example = "john.doe@gmail.com")
    @Email(message = "Please provide a valid email address")
    private String email;

    @Schema(description = "User's name from social provider", example = "John Doe")
    private String name;

    @Schema(description = "User's profile picture URL", example = "https://example.com/profile.jpg")
    private String profilePicture;
}