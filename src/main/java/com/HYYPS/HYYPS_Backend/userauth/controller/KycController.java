package com.HYYPS.HYYPS_Backend.userauth.controller;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.service.KycService;
import com.HYYPS.HYYPS_Backend.userauth.service.RateLimitService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
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
@RequestMapping("/api/kyc")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "kyc-api", description = "KYC Document Management APIs")
@SecurityRequirement(name = "Bearer Authentication")
public class KycController {

    private final KycService kycService;
    private final RateLimitService rateLimitService;

    @PostMapping("/upload")
    @Operation(
            summary = "Upload KYC documents",
            description = "Upload government ID, bank proof, and optional selfie for KYC verification"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "KYC documents uploaded successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "KYC documents uploaded successfully",
                        "data": {
                            "kycId": 1,
                            "status": "PENDING",
                            "message": "KYC documents uploaded successfully. Pending admin review."
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "400", description = "Profile verification required first"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "429", description = "Rate limit exceeded")
    })
    @PreAuthorize("hasRole('TEACHER')")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> uploadKycDocuments(
            @Valid @RequestBody KycUploadDto request,
            Authentication authentication,
            HttpServletRequest httpRequest) {

        String userEmail = authentication.getName();
        String clientIp = getClientIpAddress(httpRequest);

        log.info("KYC upload requested by: {} from IP: {}", userEmail, clientIp);
        ApiResponseDto<Map<String, Object>> response = kycService.uploadKycDocuments(userEmail, request);
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