package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.entity.RoleEntity;
import com.HYYPS.HYYPS_Backend.userauth.entity.UserRole;
import com.HYYPS.HYYPS_Backend.userauth.entity.User;
import com.HYYPS.HYYPS_Backend.userauth.entity.UserEmailHistory;
import com.HYYPS.HYYPS_Backend.userauth.repository.UserRepository;
import com.HYYPS.HYYPS_Backend.userauth.repository.UserRoleRepository;
import com.HYYPS.HYYPS_Backend.userauth.repository.UserEmailHistoryRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.LocalDate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final UserEmailHistoryRepository emailHistoryRepository;
    private final RoleService roleService;
    private final PasswordEncoder passwordEncoder;
    private final OtpService otpService;
    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // ===== EMAIL UPDATE METHODS =====

    /**
     * Step 1: Initiate email update - verify password and send OTP to new email
     */
    public ApiResponseDto<Void> initiateEmailUpdate(InitiateEmailUpdateRequestDto request, String clientIp) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentEmail = authentication.getName();

        User user = userRepository.findActiveUserByEmail(currentEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return ApiResponseDto.error("Password is incorrect");
        }

        // Check if new email is same as current
        if (currentEmail.equals(request.getNewEmail())) {
            return ApiResponseDto.error("New email must be different from current email");
        }

        // Check if new email is currently used by another user
        if (emailHistoryRepository.isEmailUsedByOtherUser(request.getNewEmail(), user.getId())) {
            return ApiResponseDto.error("This email is already in use by another user");
        }

        try {
            // Store email update request in Redis temporarily
            String updateKey = "email_update:" + currentEmail;
            String requestJson = objectMapper.writeValueAsString(request);
            redisTemplate.opsForValue().set(updateKey, requestJson, Duration.ofMinutes(15));

            // Generate and send OTP to new email
            otpService.generateAndPublishOtpEvent(
                    request.getNewEmail(),
                    user.getName(),
                    OtpEventDto.OtpEventType.EMAIL_VERIFICATION_OTP,
                    clientIp
            );

            log.info("Email update initiated for user: {} to new email: {}", currentEmail, request.getNewEmail());
            return ApiResponseDto.success("OTP sent to new email address. Please verify to complete email update.");

        } catch (Exception e) {
            log.error("Failed to initiate email update for user: {}", currentEmail, e);
            return ApiResponseDto.error("Failed to initiate email update. Please try again.");
        }
    }

    /**
     * Step 2: Confirm email update with OTP verification
     */
    public ApiResponseDto<Void> confirmEmailUpdate(ConfirmEmailUpdateRequestDto request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentEmail = authentication.getName();

        User user = userRepository.findActiveUserByEmail(currentEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        try {
            // Verify OTP for new email
            otpService.verifyOtp(request.getNewEmail(), request.getOtp());

            // Retrieve stored update request from Redis
            String updateKey = "email_update:" + currentEmail;
            String requestJson = redisTemplate.opsForValue().get(updateKey);

            if (requestJson == null) {
                return ApiResponseDto.error("Email update session expired. Please start again.");
            }

            InitiateEmailUpdateRequestDto originalRequest =
                    objectMapper.readValue(requestJson, InitiateEmailUpdateRequestDto.class);

            // Verify the new email matches the original request
            if (!originalRequest.getNewEmail().equals(request.getNewEmail())) {
                return ApiResponseDto.error("Email mismatch. Please start the process again.");
            }

            // Double-check that email is still not used by another user
            if (emailHistoryRepository.isEmailUsedByOtherUser(request.getNewEmail(), user.getId())) {
                return ApiResponseDto.error("This email is now in use by another user");
            }

            // Update email in database
            updateUserEmail(user, request.getNewEmail());

            // Clean up Redis
            redisTemplate.delete(updateKey);

            log.info("Email successfully updated for user: {} from {} to {}",
                    user.getId(), currentEmail, request.getNewEmail());

            return ApiResponseDto.success("Email updated successfully. Please log in again with your new email.");

        } catch (Exception e) {
            log.error("Failed to confirm email update for user: {}", currentEmail, e);
            return ApiResponseDto.error("Failed to update email. Please try again.");
        }
    }

    /**
     * Helper method to update user email and maintain history
     */
    private void updateUserEmail(User user, String newEmail) {
        String oldEmail = user.getEmail();
        LocalDateTime now = LocalDateTime.now();

        // Update current email history record
        emailHistoryRepository.findCurrentEmailHistory(user)
                .ifPresent(currentHistory -> {
                    currentHistory.setIsCurrent(false);
                    currentHistory.setUsedUntil(now);
                    emailHistoryRepository.save(currentHistory);
                });

        // Check if user has used this email before
        UserEmailHistory existingHistory = emailHistoryRepository.findByUserAndEmail(user, newEmail)
                .orElse(null);

        if (existingHistory != null) {
            // User is reverting to a previously used email
            existingHistory.setIsCurrent(true);
            existingHistory.setUsedFrom(now);
            existingHistory.setUsedUntil(null);
            emailHistoryRepository.save(existingHistory);
            log.info("User {} reverted to previously used email: {}", user.getId(), newEmail);
        } else {
            // User is using a completely new email
            UserEmailHistory newHistory = new UserEmailHistory();
            newHistory.setUser(user);
            newHistory.setEmail(newEmail);
            newHistory.setUsedFrom(now);
            newHistory.setIsCurrent(true);
            emailHistoryRepository.save(newHistory);
            log.info("User {} started using new email: {}", user.getId(), newEmail);
        }

        // Update user's current email and mark as unverified
        user.setEmail(newEmail);
        user.setIsEmailVerified(true); // Set to true since OTP was verified
        userRepository.save(user);
    }

    /**
     * DEPRECATED: Keep old method for backward compatibility
     * @deprecated Use initiateEmailUpdate and confirmEmailUpdate instead
     */
    @Deprecated
    public ApiResponseDto<Void> updateEmail(InitiateEmailUpdateRequestDto request) {
        return ApiResponseDto.error("This method is deprecated. Use the new email update flow with OTP verification.");
    }

    // ===== EXISTING METHODS (keeping all your existing methods unchanged) =====

    public ApiResponseDto<Map<String, Object>> getCurrentUserProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Get user roles from UserRole entity (new system)
        List<UserRole> userRoles = userRoleRepository.findByUser(user);
        List<RoleDto> roles = userRoles.stream()
                .map(userRole -> new RoleDto(
                        userRole.getRole().getRoleId(),
                        userRole.getRole().getRoleName(),
                        userRole.getIsOnboarded()
                ))
                .collect(Collectors.toList());

        // Create enhanced user profile with role information
        Map<String, Object> profileData = new HashMap<>();
        profileData.put("id", user.getId());
        profileData.put("name", user.getName());
        profileData.put("email", user.getEmail());
        profileData.put("isEmailVerified", user.getIsEmailVerified());
        profileData.put("createdAt", user.getCreatedAt());
        profileData.put("lastLogin", user.getLastLogin());
        profileData.put("totalRoles", roles.size());
        profileData.put("roles", roles);
        profileData.put("hasRoles", !roles.isEmpty());

        return ApiResponseDto.success("Profile retrieved successfully", profileData);
    }

    public ApiResponseDto<Map<String, Object>> updateProfile(UpdateProfileRequestDto request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Update fields if provided
        if (request.getName() != null && !request.getName().trim().isEmpty()) {
            user.setName(request.getName().trim());
        }
        if (request.getPhoneNumber() != null && !request.getPhoneNumber().trim().isEmpty()) {
            user.setPhoneNumber(request.getPhoneNumber().trim());
        }
        if (request.getDateOfBirth() != null && !request.getDateOfBirth().trim().isEmpty()) {
            try {
                user.setDateOfBirth(LocalDate.parse(request.getDateOfBirth()));
            } catch (Exception e) {
                return ApiResponseDto.error("Invalid date format. Use YYYY-MM-DD");
            }
        }
        if (request.getProfilePicture() != null && !request.getProfilePicture().trim().isEmpty()) {
            user.setProfilePicture(request.getProfilePicture().trim());
        }

        user = userRepository.save(user);

        // Get updated user data with roles
        List<UserRole> userRoles = userRoleRepository.findByUser(user);
        List<RoleDto> roles = userRoles.stream()
                .map(userRole -> new RoleDto(
                        userRole.getRole().getRoleId(),
                        userRole.getRole().getRoleName(),
                        userRole.getIsOnboarded()
                ))
                .collect(Collectors.toList());

        Map<String, Object> userData = new HashMap<>();
        userData.put("id", user.getId());
        userData.put("name", user.getName());
        userData.put("email", user.getEmail());
        userData.put("phoneNumber", user.getPhoneNumber());
        userData.put("dateOfBirth", user.getDateOfBirth());
        userData.put("profilePicture", user.getProfilePicture());
        userData.put("isEmailVerified", user.getIsEmailVerified());
        userData.put("createdAt", user.getCreatedAt());
        userData.put("lastLogin", user.getLastLogin());
        userData.put("totalRoles", roles.size());
        userData.put("roles", roles);

        log.info("Profile updated successfully for user: {}", email);
        return ApiResponseDto.success("Profile updated successfully", userData);
    }

    public ApiResponseDto<Void> changePassword(ChangePasswordRequestDto request) {
        // Validate passwords match
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            return ApiResponseDto.error("New passwords do not match");
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Verify current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            return ApiResponseDto.error("Current password is incorrect");
        }

        // Check if new password is different from current
        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            return ApiResponseDto.error("New password must be different from current password");
        }

        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        log.info("Password changed successfully for user: {}", email);
        return ApiResponseDto.success("Password changed successfully");
    }

    // ... (keep all your other existing methods unchanged)

    public ApiResponseDto<Map<String, Object>> assignRole(Long roleId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        RoleEntity role = roleService.findByRoleId(roleId);

        // Check if user already has this role
        if (userRoleRepository.existsByUserAndRole(user, role)) {
            return ApiResponseDto.error("Role already assigned to user");
        }

        // Create user-role mapping
        UserRole userRole = new UserRole();
        userRole.setUser(user);
        userRole.setRole(role);
        userRole.setIsOnboarded(false);
        userRoleRepository.save(userRole);

        Map<String, Object> response = new HashMap<>();
        response.put("roleId", role.getRoleId());
        response.put("roleName", role.getRoleName());
        response.put("isOnboarded", false);

        log.info("Role {} assigned to user: {}", role.getRoleName(), email);
        return ApiResponseDto.success("Role assigned successfully", response);
    }

    public ApiResponseDto<Map<String, Object>> getUserRolesWithOnboarding() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<UserRole> userRoles = userRoleRepository.findByUser(user);
        List<RoleDto> roles = userRoles.stream()
                .map(userRole -> new RoleDto(
                        userRole.getRole().getRoleId(),
                        userRole.getRole().getRoleName(),
                        userRole.getIsOnboarded()
                ))
                .collect(Collectors.toList());

        Map<String, Object> response = new HashMap<>();
        response.put("totalRoles", roles.size());
        response.put("roles", roles);

        return ApiResponseDto.success("Role status retrieved", response);
    }

    public ApiResponseDto<Void> deactivateAccount(DeactivateAccountRequestDto request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return ApiResponseDto.error("Password is incorrect");
        }

        // Deactivate account
        user.setIsActive(false);
        userRepository.save(user);

        log.info("Account deactivated for user: {}, reason: {}", email, request.getReason());
        return ApiResponseDto.success("Account deactivated successfully");
    }

    public ApiResponseDto<Map<String, Object>> removeRole(Long roleId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        RoleEntity role = roleService.findByRoleId(roleId);
        UserRole userRole = userRoleRepository.findByUserAndRole(user, role)
                .orElseThrow(() -> new RuntimeException("Role not found for user"));

        userRoleRepository.delete(userRole);

        Map<String, Object> response = new HashMap<>();
        response.put("roleId", role.getRoleId());
        response.put("roleName", role.getRoleName());

        log.info("Role {} removed from user: {}", role.getRoleName(), email);
        return ApiResponseDto.success("Role deleted successfully", response);
    }

    public ApiResponseDto<Void> completeOnboarding(Long roleId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        RoleEntity role = roleService.findByRoleId(roleId);
        UserRole userRole = userRoleRepository.findByUserAndRole(user, role)
                .orElseThrow(() -> new RuntimeException("Role not found for user"));

        userRole.setIsOnboarded(true);
        userRoleRepository.save(userRole);

        log.info("Onboarding completed for role {} by user: {}", role.getRoleName(), email);
        return ApiResponseDto.success("Onboarding completed successfully");
    }

    // Helper method to get user roles as RoleDto list
    public List<RoleDto> getUserRoles(User user) {
        List<UserRole> userRoles = userRoleRepository.findByUser(user);
        return userRoles.stream()
                .map(userRole -> new RoleDto(
                        userRole.getRole().getRoleId(),
                        userRole.getRole().getRoleName(),
                        userRole.getIsOnboarded()
                ))
                .collect(Collectors.toList());
    }

    @Deprecated
    private UserProfileDto convertToUserProfile(User user) {
        UserProfileDto profile = new UserProfileDto();
        profile.setId(user.getId());
        profile.setName(user.getName());
        profile.setEmail(user.getEmail());
        profile.setIsEmailVerified(user.getIsEmailVerified());
        profile.setRoles(user.getRoles());
        profile.setCreatedAt(user.getCreatedAt());
        profile.setLastLogin(user.getLastLogin());
        return profile;
    }
}