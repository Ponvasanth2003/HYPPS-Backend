package com.HYYPS.HYYPS_Backend.userauth.dto;

import com.HYYPS.HYYPS_Backend.userauth.entity.Role;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Set;

@Data
@Schema(description = "User profile information")
public class UserProfileDto {

    @Schema(description = "User ID", example = "1")
    private Long id;

    @Schema(description = "User's full name", example = "John Doe")
    private String name;

    @Schema(description = "User's email address", example = "john.doe@example.com")
    private String email;

    @Schema(description = "Email verification status", example = "true")
    private Boolean isEmailVerified;

    @Schema(description = "User's roles", example = "[\"STUDENT\", \"TEACHER\"]")
    private Set<Role> roles;

    @Schema(description = "Account creation timestamp", example = "2023-12-01T10:30:00")
    private LocalDateTime createdAt;

    @Schema(description = "Last login timestamp", example = "2023-12-01T15:45:00")
    private LocalDateTime lastLogin;
}