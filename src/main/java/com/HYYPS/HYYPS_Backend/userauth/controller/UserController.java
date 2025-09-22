package com.HYYPS.HYYPS_Backend.userauth.controller;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "user-management-api", description = "Handles User Management APIs")
public class UserController {

    private final UserService userService;

    // ===== NEW EMAIL UPDATE ENDPOINTS =====

    @PostMapping("/email/initiate-update")
    @Operation(
            summary = "Initiate email update",
            description = "Start the email update process by verifying password and sending OTP to new email"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OTP sent to new email successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request or email already in use"),
            @ApiResponse(responseCode = "401", description = "Unauthorized or incorrect password")
    })
    public ResponseEntity<ApiResponseDto<Void>> initiateEmailUpdate(
            @Valid @RequestBody InitiateEmailUpdateRequestDto request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        String clientIp = getClientIp(httpRequest);
        log.info("Email update initiation request received for new email: {}", request.getNewEmail());

        ApiResponseDto<Void> response = userService.initiateEmailUpdate(request, clientIp);

        // Set HttpOnly and Secure cookie if needed
        if (response.isSuccess()) {
            setSecureCookie(httpResponse, "email-update-session", "active", 900); // 15 minutes
        }

        return ResponseEntity.ok(response);
    }

    @PostMapping("/email/confirm-update")
    @Operation(
            summary = "Confirm email update with OTP",
            description = "Complete the email update process by verifying OTP sent to new email"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Email updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid OTP or request expired"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<ApiResponseDto<Void>> confirmEmailUpdate(
            @Valid @RequestBody ConfirmEmailUpdateRequestDto request,
            HttpServletResponse httpResponse) {

        log.info("Email update confirmation request received for email: {}", request.getNewEmail());
        ApiResponseDto<Void> response = userService.confirmEmailUpdate(request);

        // Clear email update session cookie
        if (response.isSuccess()) {
            clearCookie(httpResponse, "email-update-session");
        }

        return ResponseEntity.ok(response);
    }

    // ===== PROFILE MANAGEMENT ENDPOINTS =====

    @GetMapping("/profile")
    @Operation(
            summary = "Get current user profile",
            description = "Retrieve the profile information of the currently authenticated user with roles and onboarding status"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Profile retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiResponseDto.class),
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "Profile retrieved successfully",
                        "data": {
                            "id": 3,
                            "name": "Suman",
                            "email": "balasuman.s2003@gmail.com",
                            "isEmailVerified": true,
                            "createdAt": "2025-07-26T22:57:11.286866",
                            "lastLogin": "2025-08-03T18:15:31.7617403",
                            "totalRoles": 1,
                            "hasRoles": true,
                            "roles": [
                                {
                                    "roleId": 1,
                                    "roleName": "STUDENT",
                                    "isOnboarded": true
                                }
                            ]
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing authentication cookie"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getCurrentUserProfile(
            HttpServletRequest request) {

        // Authentication is handled by JWT filter using cookies
        ApiResponseDto<Map<String, Object>> response = userService.getCurrentUserProfile();
        return ResponseEntity.ok(response);
    }

    @PutMapping("/profile")
    @Operation(
            summary = "Update user profile",
            description = "Update current user's profile information"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Profile updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input data"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> updateProfile(
            @Valid @RequestBody UpdateProfileRequestDto request) {
        log.info("Profile update request received");
        ApiResponseDto<Map<String, Object>> response = userService.updateProfile(request);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/change-password")
    @Operation(
            summary = "Change user password",
            description = "Change current user's password with current password verification"
    )
    public ResponseEntity<ApiResponseDto<Void>> changePassword(
            @Valid @RequestBody ChangePasswordRequestDto request,
            HttpServletResponse httpResponse) {
        log.info("Password change request received");
        ApiResponseDto<Void> response = userService.changePassword(request);

        // Set a temporary cookie to indicate password change
        if (response.isSuccess()) {
            setSecureCookie(httpResponse, "password-changed", "true", 300); // 5 minutes
        }

        return ResponseEntity.ok(response);
    }

    // ===== DEPRECATED ENDPOINT =====
    @PutMapping("/email")
    @Operation(
            summary = "Update user email (DEPRECATED)",
            description = "DEPRECATED: Use /email/initiate-update and /email/confirm-update instead"
    )
    @Deprecated
    public ResponseEntity<ApiResponseDto<Void>> updateEmail(
            @Valid @RequestBody InitiateEmailUpdateRequestDto request) {
        log.warn("Deprecated email update endpoint called. Use new OTP-based flow instead.");
        return ResponseEntity.ok(ApiResponseDto.error("This endpoint is deprecated. Use the new email update flow with OTP verification."));
    }

    // ===== ROLE MANAGEMENT ENDPOINTS =====

    @PostMapping("/role")
    @Operation(
            summary = "Assign role to user",
            description = "Assign a specific role (student, teacher, etc.) to the current user using role ID"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Role assigned successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "Role assigned successfully",
                        "data": {
                            "roleId": 1,
                            "roleName": "STUDENT",
                            "isOnboarded": false
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "400", description = "Role already exists for user"),
            @ApiResponse(responseCode = "404", description = "Role not found")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> assignRole(
            @Valid @RequestBody
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Role assignment request",
                    content = @Content(
                            schema = @Schema(implementation = RoleRequestDto.class),
                            examples = @ExampleObject(value = """
                        {
                            "roleId": 1
                        }
                        """)
                    )
            ) RoleRequestDto request,
            HttpServletResponse httpResponse) {

        log.info("Role assignment request for roleId: {}", request.getRoleId());
        ApiResponseDto<Map<String, Object>> response = userService.assignRole(request.getRoleId());

        // Set a cookie to track role assignment
        if (response.isSuccess()) {
            setSecureCookie(httpResponse, "role-assigned", String.valueOf(request.getRoleId()), 3600); // 1 hour
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/roles")
    @Operation(
            summary = "Get user roles with onboarding status",
            description = "Get the current user's roles and their onboarding completion status"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "User roles retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "Role status retrieved",
                        "data": {
                            "totalRoles": 1,
                            "roles": [
                                {
                                    "roleId": 1,
                                    "roleName": "STUDENT",
                                    "isOnboarded": true
                                }
                            ]
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing authentication cookie"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getUserRoles() {
        ApiResponseDto<Map<String, Object>> response = userService.getUserRolesWithOnboarding();
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/role/{roleId}")
    @Operation(
            summary = "Remove role from user",
            description = "Remove a specific role from the current user"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Role removed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "Role deleted successfully",
                        "data": {
                            "roleId": 2,
                            "roleName": "TEACHER"
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "404", description = "Role not found for user")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> removeRole(
            @Parameter(description = "Role ID to remove", example = "2")
            @PathVariable Long roleId,
            HttpServletResponse httpResponse) {

        log.info("Role removal request for roleId: {}", roleId);
        ApiResponseDto<Map<String, Object>> response = userService.removeRole(roleId);

        // Clear role-related cookies
        if (response.isSuccess()) {
            clearCookie(httpResponse, "role-assigned");
        }

        return ResponseEntity.ok(response);
    }

    // ===== ACCOUNT MANAGEMENT ENDPOINTS =====

    @PostMapping("/deactivate")
    @Operation(
            summary = "Deactivate user account",
            description = "Deactivate current user's account with password verification"
    )
    public ResponseEntity<ApiResponseDto<Void>> deactivateAccount(
            @Valid @RequestBody DeactivateAccountRequestDto request,
            HttpServletResponse httpResponse) {
        log.info("Account deactivation request received");
        ApiResponseDto<Void> response = userService.deactivateAccount(request);

        // Clear all user-related cookies on deactivation
        if (response.isSuccess()) {
            clearCookie(httpResponse, "auth-token");
            clearCookie(httpResponse, "refresh-token");
            clearCookie(httpResponse, "role-assigned");
            clearCookie(httpResponse, "email-update-session");
            clearCookie(httpResponse, "password-changed");
        }

        return ResponseEntity.ok(response);
    }

    // ===== UTILITY METHODS =====

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }

    /**
     * Set a secure HttpOnly cookie
     */
    private void setSecureCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        cookie.setAttribute("SameSite", "Strict");
        response.addCookie(cookie);
    }

    /**
     * Clear a cookie by setting its max age to 0
     */
    private void clearCookie(HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}