package com.HYYPS.HYYPS_Backend.userauth.controller;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.entity.Role;
import com.HYYPS.HYYPS_Backend.userauth.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "user-management-api", description = "Handles User Management APIs")
@SecurityRequirement(name = "Bearer Authentication")
public class UserController {

    private final UserService userService;

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
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getCurrentUserProfile() {
        ApiResponseDto<Map<String, Object>> response = userService.getCurrentUserProfile();
        return ResponseEntity.ok(response);
    }

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
            ) RoleRequestDto request) {

        log.info("Role assignment request for roleId: {}", request.getRoleId());
        ApiResponseDto<Map<String, Object>> response = userService.assignRole(request.getRoleId());
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
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token"),
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
            @PathVariable Long roleId) {

        log.info("Role removal request for roleId: {}", roleId);
        ApiResponseDto<Map<String, Object>> response = userService.removeRole(roleId);
        return ResponseEntity.ok(response);
    }
}