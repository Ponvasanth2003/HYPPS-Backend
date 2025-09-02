package com.HYYPS.HYYPS_Backend.userauth.controller;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.service.AdminService;
import com.HYYPS.HYYPS_Backend.userauth.service.KycService;
import com.HYYPS.HYYPS_Backend.userauth.service.SecurityService;
import com.HYYPS.HYYPS_Backend.userauth.service.TeacherVerificationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
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
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "admin-api", description = "Admin Management APIs")
@SecurityRequirement(name = "Bearer Authentication")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final AdminService adminService;
    private final SecurityService securityService;
    private final TeacherVerificationService teacherVerificationService;
    private final KycService kycService;

    // =============================================================================
    // USER MANAGEMENT
    // =============================================================================

    @GetMapping("/users")
    @Operation(
            summary = "Get all users with pagination and search",
            description = "Retrieve all users with pagination, sorting, and search functionality"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Users retrieved successfully"),
            @ApiResponse(responseCode = "403", description = "Admin access required")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getAllUsers(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "20") int size,
            @Parameter(description = "Sort field")
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @Parameter(description = "Sort direction (asc/desc)")
            @RequestParam(defaultValue = "desc") String sortDir,
            @Parameter(description = "Search term for name or email")
            @RequestParam(required = false) String search) {

        log.info("Admin requesting all users - page: {}, size: {}, search: {}", page, size, search);
        ApiResponseDto<Map<String, Object>> response =
                adminService.getAllUsers(page, size, sortBy, sortDir, search);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/users/{userId}")
    @Operation(summary = "Get user by ID", description = "Retrieve detailed user information by ID")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getUserById(
            @Parameter(description = "User ID")
            @PathVariable Long userId) {
        log.info("Admin requesting user details for userId: {}", userId);
        ApiResponseDto<Map<String, Object>> response = adminService.getUserById(userId);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/users/{userId}")
    @Operation(summary = "Update user by admin", description = "Update user information as admin")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> updateUser(
            @Parameter(description = "User ID")
            @PathVariable Long userId,
            @Valid @RequestBody AdminUpdateUserRequestDto request) {
        log.info("Admin updating user: {}", userId);
        ApiResponseDto<Map<String, Object>> response = adminService.updateUser(userId, request);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/users/{userId}")
    @Operation(summary = "Delete user", description = "Permanently delete user and all associated data")
    public ResponseEntity<ApiResponseDto<Void>> deleteUser(
            @Parameter(description = "User ID")
            @PathVariable Long userId) {
        log.info("Admin deleting user: {}", userId);
        ApiResponseDto<Void> response = adminService.deleteUser(userId);
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/users/{userId}/status")
    @Operation(summary = "Update user status", description = "Activate or deactivate user account")
    public ResponseEntity<ApiResponseDto<Void>> updateUserStatus(
            @Parameter(description = "User ID")
            @PathVariable Long userId,
            @Valid @RequestBody UpdateUserStatusRequestDto request) {
        log.info("Admin updating user status for userId: {}, active: {}", userId, request.getIsActive());
        ApiResponseDto<Void> response = adminService.updateUserStatus(userId, request);
        return ResponseEntity.ok(response);
    }

    // =============================================================================
    // ROLE MANAGEMENT
    // =============================================================================

    @PostMapping("/roles")
    @Operation(summary = "Create new role", description = "Create a new role in the system")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> createRole(
            @Valid @RequestBody CreateRoleRequestDto request) {
        log.info("Admin creating new role: {}", request.getRoleName());
        ApiResponseDto<Map<String, Object>> response = adminService.createRole(request);
        return ResponseEntity.status(201).body(response);
    }

    @PutMapping("/roles/{roleId}")
    @Operation(summary = "Update role", description = "Update existing role information")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> updateRole(
            @Parameter(description = "Role ID")
            @PathVariable Long roleId,
            @Valid @RequestBody UpdateRoleRequestDto request) {
        log.info("Admin updating role: {}", roleId);
        ApiResponseDto<Map<String, Object>> response = adminService.updateRole(roleId, request);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/roles/{roleId}")
    @Operation(summary = "Delete role", description = "Delete role from system")
    public ResponseEntity<ApiResponseDto<Void>> deleteRole(
            @Parameter(description = "Role ID")
            @PathVariable Long roleId) {
        log.info("Admin deleting role: {}", roleId);
        ApiResponseDto<Void> response = adminService.deleteRole(roleId);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/users/{userId}/roles")
    @Operation(summary = "Assign role to user", description = "Assign a role to specific user")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> assignRoleToUser(
            @Parameter(description = "User ID")
            @PathVariable Long userId,
            @Valid @RequestBody AssignRoleRequestDto request) {
        log.info("Admin assigning role {} to user {}", request.getRoleId(), userId);
        ApiResponseDto<Map<String, Object>> response = adminService.assignRoleToUser(userId, request);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/users/{userId}/roles/{roleId}")
    @Operation(summary = "Remove role from user", description = "Remove specific role from user")
    public ResponseEntity<ApiResponseDto<Void>> removeRoleFromUser(
            @Parameter(description = "User ID")
            @PathVariable Long userId,
            @Parameter(description = "Role ID")
            @PathVariable Long roleId) {
        log.info("Admin removing role {} from user {}", roleId, userId);
        ApiResponseDto<Void> response = adminService.removeRoleFromUser(userId, roleId);
        return ResponseEntity.ok(response);
    }

    // =============================================================================
    // TEACHER VERIFICATION MANAGEMENT
    // =============================================================================

    @GetMapping("/verifications/pending")
    @Operation(summary = "Get pending teacher verifications", description = "Retrieve all pending teacher profile verifications")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getPendingVerifications(
            @Parameter(description = "Page number")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "20") int size) {

        log.info("Admin requesting pending verifications - page: {}, size: {}", page, size);
        ApiResponseDto<Map<String, Object>> response = teacherVerificationService.getPendingVerifications(page, size);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verifications/{verificationId}")
    @Operation(summary = "Verify or reject teacher profile", description = "Admin action to verify or reject teacher profile")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> verifyProfile(
            @Parameter(description = "Verification ID")
            @PathVariable Long verificationId,
            @Valid @RequestBody ProfileVerificationRequestDto request) {

        log.info("Admin {} profile for verificationId: {}", request.getAction().toLowerCase(), verificationId);
        ApiResponseDto<Map<String, Object>> response = teacherVerificationService.verifyProfile(verificationId, request);
        return ResponseEntity.ok(response);
    }

    // =============================================================================
    // KYC MANAGEMENT
    // =============================================================================

    @GetMapping("/kyc/pending")
    @Operation(summary = "Get pending KYC submissions", description = "Retrieve all pending KYC submissions for admin review")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getPendingKycSubmissions(
            @Parameter(description = "Page number")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "20") int size) {

        log.info("Admin requesting pending KYC submissions - page: {}, size: {}", page, size);
        ApiResponseDto<Map<String, Object>> response = kycService.getPendingKycSubmissions(page, size);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/kyc/{kycId}/verify")
    @Operation(summary = "Verify or reject KYC submission", description = "Admin action to verify or reject KYC documents")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> verifyKyc(
            @Parameter(description = "KYC submission ID")
            @PathVariable Long kycId,
            @Valid @RequestBody KycVerificationRequestDto request) {

        log.info("Admin {} KYC for kycId: {}", request.getAction().toLowerCase(), kycId);
        ApiResponseDto<Map<String, Object>> response = kycService.verifyKyc(kycId, request);
        return ResponseEntity.ok(response);
    }

    // =============================================================================
    // ANALYTICS
    // =============================================================================

    @GetMapping("/analytics/users")
    @Operation(summary = "Get user analytics", description = "Retrieve comprehensive user statistics")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getUserAnalytics() {
        log.info("Admin requesting user analytics");
        ApiResponseDto<Map<String, Object>> response = adminService.getUserAnalytics();
        return ResponseEntity.ok(response);
    }

    @GetMapping("/analytics/logins")
    @Operation(summary = "Get login analytics", description = "Retrieve login statistics and trends")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getLoginAnalytics(
            @Parameter(description = "Time period (7days, 30days, 90days)")
            @RequestParam(defaultValue = "7days") String period) {
        log.info("Admin requesting login analytics for period: {}", period);
        ApiResponseDto<Map<String, Object>> response = adminService.getLoginAnalytics(period);
        return ResponseEntity.ok(response);
    }

    // =============================================================================
    // SECURITY MANAGEMENT
    // =============================================================================

    @GetMapping("/security/events")
    @Operation(summary = "Get security events", description = "Retrieve security events with filtering")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getSecurityEvents(
            @Parameter(description = "Page number")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "50") int size,
            @Parameter(description = "Event type filter")
            @RequestParam(required = false) String eventType,
            @Parameter(description = "User email filter")
            @RequestParam(required = false) String userEmail) {
        log.info("Admin requesting security events - page: {}, eventType: {}", page, eventType);
        ApiResponseDto<Map<String, Object>> response =
                securityService.getSecurityEvents(page, size, eventType, userEmail);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/security/suspicious-activity")
    @Operation(summary = "Get suspicious activities", description = "Retrieve potential security threats")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getSuspiciousActivity() {
        log.info("Admin requesting suspicious activity report");
        ApiResponseDto<Map<String, Object>> response = securityService.getSuspiciousActivity();
        return ResponseEntity.ok(response);
    }

    @PostMapping("/security/block-ip")
    @Operation(summary = "Block IP address", description = "Block specific IP address from accessing the system")
    public ResponseEntity<ApiResponseDto<Void>> blockIpAddress(
            @Valid @RequestBody BlockIpRequestDto request) {
        log.info("Admin blocking IP address: {}", request.getIpAddress());
        ApiResponseDto<Void> response = securityService.blockIpAddress(request);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/security/block-ip/{ipAddress}")
    @Operation(summary = "Unblock IP address", description = "Remove IP address from blocklist")
    public ResponseEntity<ApiResponseDto<Void>> unblockIpAddress(
            @Parameter(description = "IP address to unblock")
            @PathVariable String ipAddress) {
        log.info("Admin unblocking IP address: {}", ipAddress);
        ApiResponseDto<Void> response = securityService.unblockIpAddress(ipAddress);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/security/blocked-ips")
    @Operation(summary = "Get blocked IP addresses", description = "Retrieve list of currently blocked IPs")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getBlockedIps() {
        log.info("Admin requesting blocked IPs list");
        ApiResponseDto<Map<String, Object>> response = securityService.getBlockedIps();
        return ResponseEntity.ok(response);
    }

    // =============================================================================
    // SYSTEM MANAGEMENT
    // =============================================================================

    @GetMapping("/system/stats")
    @Operation(summary = "Get system statistics", description = "Retrieve comprehensive system statistics")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getSystemStats() {
        log.info("Admin requesting system statistics");
        ApiResponseDto<Map<String, Object>> response = adminService.getSystemStats();
        return ResponseEntity.ok(response);
    }

    @PostMapping("/system/maintenance")
    @Operation(summary = "Toggle maintenance mode", description = "Enable or disable system maintenance mode")
    public ResponseEntity<ApiResponseDto<Void>> toggleMaintenanceMode(
            @Parameter(description = "Enable/disable maintenance mode")
            @RequestParam boolean enabled,
            @Parameter(description = "Maintenance message")
            @RequestParam(required = false) String message) {
        log.info("Admin toggling maintenance mode: enabled={}, message={}", enabled, message);
        ApiResponseDto<Void> response = adminService.toggleMaintenanceMode(enabled, message);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/system/maintenance")
    @Operation(summary = "Get maintenance status", description = "Check if system is in maintenance mode")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getMaintenanceStatus() {
        log.info("Checking maintenance status");
        ApiResponseDto<Map<String, Object>> response = adminService.getMaintenanceStatus();
        return ResponseEntity.ok(response);
    }
}