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
@Tag(name = "onboarding-api", description = "User Onboarding APIs - Uses HttpOnly Cookie Authentication")
public class OnboardingController {

    private final OnboardingService onboardingService;

    // ===== ROLE-BASED ONBOARDING ENDPOINTS =====

    @PostMapping("/role/{roleId}")
    @Operation(
            summary = "Submit onboarding for specific role",
            description = "Submit onboarding form (teacher or student) based on role ID. Authentication via HttpOnly cookie."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Onboarding submitted successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Teacher Onboarding Success",
                                            value = """
                                    {
                                        "success": true,
                                        "message": "Teacher onboarding submitted successfully",
                                        "data": {
                                            "roleId": 2,
                                            "roleName": "TEACHER",
                                            "message": "Teacher onboarding submitted successfully",
                                            "isCompleted": true,
                                            "redirectTo": "teacher-dashboard"
                                        },
                                        "timestamp": 1703123456789
                                    }
                                    """
                                    ),
                                    @ExampleObject(
                                            name = "Student Onboarding Success",
                                            value = """
                                    {
                                        "success": true,
                                        "message": "Student onboarding submitted successfully",
                                        "data": {
                                            "roleId": 1,
                                            "roleName": "STUDENT",
                                            "message": "Student onboarding submitted successfully",
                                            "isCompleted": true,
                                            "redirectTo": "class-discovery"
                                        },
                                        "timestamp": 1703123456789
                                    }
                                    """
                                    )
                            }
                    )
            ),
            @ApiResponse(responseCode = "400", description = "Invalid onboarding data or role mismatch"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing HttpOnly cookie"),
            @ApiResponse(responseCode = "404", description = "Role not found or not assigned to user")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> submitOnboarding(
            @Parameter(description = "Role ID (1 for STUDENT, 2 for TEACHER)", example = "1")
            @PathVariable Long roleId,
            @Valid @RequestBody
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Onboarding data - can be TeacherOnboardingDto or StudentOnboardingDto based on role",
                    content = {
                            @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = TeacherOnboardingDto.class),
                                    examples = @ExampleObject(
                                            name = "Teacher Onboarding",
                                            value = """
                                    {
                                        "profilePhoto": "https://s3.amazonaws.com/photos/teacher.jpg",
                                        "name": "John Smith",
                                        "bio": "Experienced mathematics teacher with 10+ years of teaching",
                                        "subject": "Mathematics",
                                        "teachingLevel": "INTERMEDIATE",
                                        "hasCertificate": true,
                                        "certificateUrl": "https://s3.amazonaws.com/certificates/cert.pdf",
                                        "classType": "BOTH",
                                        "freeClassAmount": 2000,
                                        "weeklySchedule": "Monday: 9AM-5PM, Tuesday: 10AM-6PM",
                                        "firstClassTitle": "Introduction to Algebra",
                                        "firstClassDescription": "Basic concepts of algebra for beginners",
                                        "courseDurationDays": 30,
                                        "batchesPerDay": 2,
                                        "batchDurationMinutes": 60,
                                        "maxStudentsPerBatch": 20,
                                        "completeSetup": true
                                    }
                                    """
                                    )
                            ),
                            @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = StudentOnboardingDto.class),
                                    examples = @ExampleObject(
                                            name = "Student Onboarding",
                                            value = """
                                    {
                                        "profilePhoto": "https://s3.amazonaws.com/photos/student.jpg",
                                        "name": "Jane Doe",
                                        "interestedSubjects": ["Mathematics", "Physics"],
                                        "learningPreference": "BEGINNER",
                                        "preferredLearningType": "BOTH",
                                        "readyToStart": "FIND_CLASSES",
                                        "completeSetup": true
                                    }
                                    """
                                    )
                            )
                    }
            ) Object request) {

        log.info("Onboarding submission received for roleId: {}", roleId);
        ApiResponseDto<Map<String, Object>> response = onboardingService.submitOnboardingByRoleId(roleId, request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/complete/{roleId}")
    @Operation(
            summary = "Complete onboarding for specific role",
            description = "Mark onboarding as completed for a specific role ID. Authentication via HttpOnly cookie."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Onboarding completed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "Onboarding completed successfully",
                        "data": {
                            "roleId": 1,
                            "roleName": "STUDENT",
                            "isOnboarded": true,
                            "completedAt": "2025-08-27T10:30:00"
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "400", description = "Onboarding already completed"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing HttpOnly cookie"),
            @ApiResponse(responseCode = "404", description = "Role not found or not assigned to user")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> completeOnboarding(
            @Parameter(description = "Role ID to complete onboarding for", example = "1")
            @PathVariable Long roleId) {

        log.info("Onboarding completion request for roleId: {}", roleId);
        ApiResponseDto<Map<String, Object>> response = onboardingService.completeOnboardingByRoleId(roleId);
        return ResponseEntity.ok(response);
    }

    // ===== CLASS DISCOVERY ENDPOINT =====

    @PostMapping("/class-discovery")
    @Operation(
            summary = "Process class discovery form",
            description = "Process class discovery form when student chooses 'Yes, let's find classes!'. Authentication via HttpOnly cookie."
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
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing HttpOnly cookie")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> processClassDiscovery(
            @Valid @RequestBody ClassDiscoveryDto request) {

        log.info("Class discovery form submitted");
        ApiResponseDto<Map<String, Object>> response = onboardingService.getClassDiscovery(request);
        return ResponseEntity.ok(response);
    }

    // ===== ONBOARDING DATA RETRIEVAL =====

    @GetMapping("/role/{roleId}")
    @Operation(
            summary = "Get onboarding data by role ID",
            description = "Retrieve existing onboarding data for a specific role ID. Authentication via HttpOnly cookie."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Onboarding data retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Teacher Onboarding Data",
                                            value = """
                                    {
                                        "success": true,
                                        "message": "Onboarding data retrieved successfully",
                                        "data": {
                                            "id": 1,
                                            "roleId": 2,
                                            "roleName": "TEACHER",
                                            "profilePhoto": "https://s3.amazonaws.com/photos/teacher.jpg",
                                            "fullName": "John Smith",
                                            "bio": "Experienced mathematics teacher",
                                            "subject": "Mathematics",
                                            "teachingLevel": "INTERMEDIATE",
                                            "hasCertificate": true,
                                            "certificateUrl": "https://s3.amazonaws.com/certificates/cert.pdf",
                                            "classType": "BOTH",
                                            "freeClassAmount": 2000,
                                            "weeklySchedule": "Monday: 9AM-5PM",
                                            "isCompleted": true,
                                            "createdAt": "2025-08-27T09:00:00",
                                            "updatedAt": "2025-08-27T10:30:00"
                                        },
                                        "timestamp": 1703123456789
                                    }
                                    """
                                    ),
                                    @ExampleObject(
                                            name = "Student Onboarding Data",
                                            value = """
                                    {
                                        "success": true,
                                        "message": "Onboarding data retrieved successfully",
                                        "data": {
                                            "id": 2,
                                            "roleId": 1,
                                            "roleName": "STUDENT",
                                            "profilePhoto": "https://s3.amazonaws.com/photos/student.jpg",
                                            "fullName": "Jane Doe",
                                            "interestedSubjects": "Mathematics,Physics",
                                            "learningPreference": "BEGINNER",
                                            "preferredLearningType": "BOTH",
                                            "readyToStart": "FIND_CLASSES",
                                            "isCompleted": true,
                                            "createdAt": "2025-08-27T09:15:00",
                                            "updatedAt": "2025-08-27T10:00:00"
                                        },
                                        "timestamp": 1703123456789
                                    }
                                    """
                                    )
                            }
                    )
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "No onboarding data found",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "No onboarding data found",
                        "data": null,
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing HttpOnly cookie"),
            @ApiResponse(responseCode = "404", description = "Role not found or not assigned to user")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getOnboardingData(
            @Parameter(description = "Role ID (1 for STUDENT, 2 for TEACHER)", example = "1")
            @PathVariable Long roleId) {

        log.info("Retrieving onboarding data for roleId: {}", roleId);
        ApiResponseDto<Map<String, Object>> response = onboardingService.getOnboardingDataByRoleId(roleId);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/status/{roleId}")
    @Operation(
            summary = "Get onboarding status for role",
            description = "Check if onboarding is completed for a specific role ID. Authentication via HttpOnly cookie."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Onboarding status retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "Onboarding status retrieved",
                        "data": {
                            "roleId": 1,
                            "roleName": "STUDENT",
                            "isOnboarded": true,
                            "hasOnboardingData": true,
                            "completedAt": "2025-08-27T10:30:00"
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing HttpOnly cookie"),
            @ApiResponse(responseCode = "404", description = "Role not found or not assigned to user")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getOnboardingStatus(
            @Parameter(description = "Role ID to check status for", example = "1")
            @PathVariable Long roleId) {

        log.info("Checking onboarding status for roleId: {}", roleId);
        ApiResponseDto<Map<String, Object>> response = onboardingService.getOnboardingStatusByRoleId(roleId);
        return ResponseEntity.ok(response);
    }

    // ===== LEGACY ENDPOINTS (DEPRECATED) =====

    @PostMapping("/teacher")
    @Operation(
            summary = "Submit teacher onboarding (DEPRECATED)",
            description = "DEPRECATED: Use POST /api/onboarding/role/{roleId} with roleId=2 instead",
            deprecated = true
    )
    @Deprecated
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> submitTeacherOnboarding(
            @Valid @RequestBody TeacherOnboardingDto request) {

        log.warn("Deprecated teacher onboarding endpoint called. Use role-based endpoint instead.");
        return ResponseEntity.ok(ApiResponseDto.error("This endpoint is deprecated. Use POST /api/onboarding/role/2 instead."));
    }

    @PostMapping("/student")
    @Operation(
            summary = "Submit student onboarding (DEPRECATED)",
            description = "DEPRECATED: Use POST /api/onboarding/role/{roleId} with roleId=1 instead",
            deprecated = true
    )
    @Deprecated
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> submitStudentOnboarding(
            @Valid @RequestBody StudentOnboardingDto request) {

        log.warn("Deprecated student onboarding endpoint called. Use role-based endpoint instead.");
        return ResponseEntity.ok(ApiResponseDto.error("This endpoint is deprecated. Use POST /api/onboarding/role/1 instead."));
    }

    @GetMapping("/{roleName}")
    @Operation(
            summary = "Get onboarding data by role name (DEPRECATED)",
            description = "DEPRECATED: Use GET /api/onboarding/role/{roleId} instead",
            deprecated = true
    )
    @Deprecated
    public ResponseEntity<ApiResponseDto<OnboardingEntity>> getOnboardingDataByRoleName(
            @Parameter(description = "Role name (DEPRECATED)", example = "STUDENT")
            @PathVariable String roleName) {

        log.warn("Deprecated get onboarding data endpoint called. Use role-based endpoint instead.");
        return ResponseEntity.ok(ApiResponseDto.error("This endpoint is deprecated. Use GET /api/onboarding/role/{roleId} instead."));
    }
}