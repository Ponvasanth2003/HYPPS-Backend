package com.HYYPS.HYYPS_Backend.userauth.controller;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.service.RateLimitService;
import com.HYYPS.HYYPS_Backend.userauth.service.TeacherVerificationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/teacher/verification")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "teacher-verification-api", description = "Teacher Verification Management APIs - Uses HttpOnly Cookie Authentication")
public class TeacherVerificationController {

    private final TeacherVerificationService teacherVerificationService;
    private final RateLimitService rateLimitService;

    @GetMapping("/dashboard")
    @Operation(
            summary = "Get teacher dashboard data",
            description = "Retrieve complete teacher dashboard with verification status and timer information. Authentication via HttpOnly cookie."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Dashboard data retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "Dashboard data retrieved successfully",
                        "data": {
                            "profileVerification": {
                                "status": "PENDING",
                                "submissionType": "CERTIFICATE",
                                "title": "Profile Verification Pending",
                                "description": "Your certificate is under admin review",
                                "canReupload": false,
                                "retryCount": 0
                            },
                            "kycVerification": {
                                "status": "LOCKED",
                                "title": "KYC Verification Locked", 
                                "description": "Complete profile verification first",
                                "canUpload": false
                            },
                            "timerInfo": {
                                "isActive": true,
                                "startedAt": "2025-08-27T10:00:00",
                                "expiresAt": "2025-08-29T10:00:00",
                                "remainingDays": 1,
                                "remainingHours": 12,
                                "remainingMinutes": 30,
                                "message": "1.5 days remaining"
                            },
                            "canCreatePaidClasses": false,
                            "nextSteps": "Wait for admin to review your profile submission"
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing HttpOnly cookie"),
            @ApiResponse(responseCode = "403", description = "Teacher role required")
    })
    @PreAuthorize("hasRole('TEACHER')")
    public ResponseEntity<ApiResponseDto<TeacherDashboardDto>> getDashboard(Authentication authentication) {
        String userEmail = authentication.getName();

        // Rate limiting for dashboard requests
        String rateLimitKey = "dashboard:" + userEmail;
        rateLimitService.checkRateLimit(rateLimitKey, 1, 60, "Too many dashboard requests");

        log.info("Teacher dashboard requested by: {}", userEmail);
        ApiResponseDto<TeacherDashboardDto> response = teacherVerificationService.getDashboardData(userEmail);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/reupload")
    @Operation(
            summary = "Reupload verification file",
            description = "Reupload certificate or video after rejection. Authentication via HttpOnly cookie."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "File reuploaded successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "File reuploaded successfully",
                        "data": {
                            "message": "File uploaded successfully. Pending admin review.",
                            "retryCount": 2,
                            "status": "PENDING"
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "400", description = "Reupload not allowed or invalid file"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing HttpOnly cookie"),
            @ApiResponse(responseCode = "403", description = "Teacher role required"),
            @ApiResponse(responseCode = "429", description = "Rate limit exceeded")
    })
    @PreAuthorize("hasRole('TEACHER')")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> reuploadFile(
            @Valid @RequestBody FileReuploadDto request,
            Authentication authentication,
            HttpServletRequest httpRequest) {

        String userEmail = authentication.getName();
        String clientIp = getClientIpAddress(httpRequest);

        // Rate limiting for file uploads
        String rateLimitKey = "file_reupload:" + userEmail;
        rateLimitService.checkRateLimit(rateLimitKey, 60, 3, "Too many reupload attempts. Please try again later.");

        log.info("File reupload requested by: {} from IP: {}", userEmail, clientIp);
        ApiResponseDto<Map<String, Object>> response = teacherVerificationService.reuploadFile(userEmail, request);
        return ResponseEntity.ok(response);
    }

    private String getClientIpAddress(HttpServletRequest request) {
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
}