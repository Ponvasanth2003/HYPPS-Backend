package com.HYYPS.HYYPS_Backend.userauth.controller;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.entity.OnboardingEntity;
import com.HYYPS.HYYPS_Backend.userauth.service.OnboardingService;
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
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/onboarding")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "onboarding-api", description = "Handles User Onboarding APIs")
@SecurityRequirement(name = "Bearer Authentication")
public class OnboardingController {

    private final OnboardingService onboardingService;

    @PostMapping("/teacher")
    @Operation(
            summary = "Submit teacher onboarding",
            description = "Submit teacher onboarding form with all required information"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Teacher onboarding submitted successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "Teacher onboarding submitted successfully",
                        "data": {
                            "message": "Teacher onboarding submitted successfully",
                            "isCompleted": true,
                            "redirectTo": "teacher-dashboard"
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "400", description = "Invalid onboarding data"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> submitTeacherOnboarding(
            @Valid @RequestBody TeacherOnboardingDto request) {

        log.info("Teacher onboarding submission received");
        ApiResponseDto<Map<String, Object>> response = onboardingService.submitTeacherOnboarding(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/student")
    @Operation(
            summary = "Submit student onboarding",
            description = "Submit student onboarding form with learning preferences"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Student onboarding submitted successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "Student onboarding submitted successfully",
                        "data": {
                            "message": "Student onboarding submitted successfully",
                            "isCompleted": true,
                            "redirectTo": "class-discovery"
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "400", description = "Invalid onboarding data"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> submitStudentOnboarding(
            @Valid @RequestBody StudentOnboardingDto request) {

        log.info("Student onboarding submission received");
        ApiResponseDto<Map<String, Object>> response = onboardingService.submitStudentOnboarding(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/class-discovery")
    @Operation(
            summary = "Process class discovery form",
            description = "Process class discovery form when student chooses 'Yes, let's find classes!'"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Class discovery completed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "Class discovery completed",
                        "data": {
                            "searchCriteria": {
                                "subjects": ["Mathematics", "Physics"],
                                "level": "BEGINNER",
                                "type": "BOTH"
                            },
                            "message": "Class discovery completed. Redirecting to browse classes."
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> processClassDiscovery(
            @Valid @RequestBody ClassDiscoveryDto request) {

        log.info("Class discovery form submitted");
        ApiResponseDto<Map<String, Object>> response = onboardingService.getClassDiscovery(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{roleName}")
    @Operation(
            summary = "Get onboarding data",
            description = "Retrieve existing onboarding data for a specific role"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Onboarding data retrieved successfully"
            ),
            @ApiResponse(responseCode = "404", description = "No onboarding data found"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<ApiResponseDto<OnboardingEntity>> getOnboardingData(
            @Parameter(description = "Role name (STUDENT or TEACHER)", example = "STUDENT")
            @PathVariable String roleName) {

        log.info("Retrieving onboarding data for role: {}", roleName);
        ApiResponseDto<OnboardingEntity> response = onboardingService.getOnboardingData(roleName);
        return ResponseEntity.ok(response);
    }
}