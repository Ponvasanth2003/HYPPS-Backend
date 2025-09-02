package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.entity.*;
import com.HYYPS.HYYPS_Backend.userauth.repository.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class OnboardingService {

    private final OnboardingRepository onboardingRepository;
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final RoleService roleService;
    private final TeacherVerificationService teacherVerificationService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // ===== NEW ROLE ID BASED METHODS =====

    /**
     * Submit onboarding data based on role ID
     */
    public ApiResponseDto<Map<String, Object>> submitOnboardingByRoleId(Long roleId, Object request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        RoleEntity role = roleService.findByRoleId(roleId);

        // Check if user has this role
        UserRole userRole = userRoleRepository.findByUserAndRole(user, role)
                .orElseThrow(() -> new RuntimeException("Role not found for user. Please assign the role first."));

        // Route to appropriate handler based on role name
        switch (role.getRoleName().toUpperCase()) {
            case "TEACHER":
                return handleTeacherOnboarding(user, role, userRole, request);
            case "STUDENT":
                return handleStudentOnboarding(user, role, userRole, request);
            default:
                return ApiResponseDto.error("Onboarding not supported for role: " + role.getRoleName());
        }
    }

    /**
     * Complete onboarding for specific role ID
     */
    public ApiResponseDto<Map<String, Object>> completeOnboardingByRoleId(Long roleId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        RoleEntity role = roleService.findByRoleId(roleId);
        UserRole userRole = userRoleRepository.findByUserAndRole(user, role)
                .orElseThrow(() -> new RuntimeException("Role not found for user"));

        if (userRole.getIsOnboarded()) {
            return ApiResponseDto.error("Onboarding already completed for this role");
        }

        // Mark as onboarded
        userRole.setIsOnboarded(true);
        userRoleRepository.save(userRole);

        // Update onboarding data if exists
        onboardingRepository.findByUserAndRole(user, role).ifPresent(onboarding -> {
            onboarding.setIsCompleted(true);
            onboardingRepository.save(onboarding);
        });

        Map<String, Object> response = new HashMap<>();
        response.put("roleId", role.getRoleId());
        response.put("roleName", role.getRoleName());
        response.put("isOnboarded", true);
        response.put("completedAt", LocalDateTime.now());

        log.info("Onboarding completed for roleId: {} by user: {}", roleId, email);
        return ApiResponseDto.success("Onboarding completed successfully", response);
    }

    /**
     * Get onboarding data by role ID
     */
    public ApiResponseDto<Map<String, Object>> getOnboardingDataByRoleId(Long roleId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        RoleEntity role = roleService.findByRoleId(roleId);

        // Check if user has this role
        if (!userRoleRepository.existsByUserAndRole(user, role)) {
            throw new RuntimeException("Role not found for user. Please assign the role first.");
        }

        OnboardingEntity onboarding = onboardingRepository.findByUserAndRole(user, role).orElse(null);

        if (onboarding == null) {
            return ApiResponseDto.success("No onboarding data found", null);
        }

        // Convert to response map with enhanced data
        Map<String, Object> onboardingData = convertOnboardingToMap(onboarding);
        onboardingData.put("roleId", role.getRoleId());
        onboardingData.put("roleName", role.getRoleName());

        return ApiResponseDto.success("Onboarding data retrieved successfully", onboardingData);
    }

    /**
     * Get onboarding status by role ID
     */
    public ApiResponseDto<Map<String, Object>> getOnboardingStatusByRoleId(Long roleId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        RoleEntity role = roleService.findByRoleId(roleId);
        UserRole userRole = userRoleRepository.findByUserAndRole(user, role)
                .orElseThrow(() -> new RuntimeException("Role not found for user"));

        OnboardingEntity onboarding = onboardingRepository.findByUserAndRole(user, role).orElse(null);

        Map<String, Object> status = new HashMap<>();
        status.put("roleId", role.getRoleId());
        status.put("roleName", role.getRoleName());
        status.put("isOnboarded", userRole.getIsOnboarded());
        status.put("hasOnboardingData", onboarding != null);
        status.put("completedAt", onboarding != null ? onboarding.getUpdatedAt() : null);

        return ApiResponseDto.success("Onboarding status retrieved", status);
    }

    // ===== PRIVATE HELPER METHODS =====

    private ApiResponseDto<Map<String, Object>> handleTeacherOnboarding(User user, RoleEntity role, UserRole userRole, Object request) {
        try {
            // Convert request to TeacherOnboardingDto
            TeacherOnboardingDto teacherRequest;
            if (request instanceof TeacherOnboardingDto) {
                teacherRequest = (TeacherOnboardingDto) request;
            } else {
                // Convert from generic object (e.g., LinkedHashMap from JSON)
                teacherRequest = objectMapper.convertValue(request, TeacherOnboardingDto.class);
            }

            // Create or update onboarding data
            OnboardingEntity onboarding = onboardingRepository.findByUserAndRole(user, role)
                    .orElse(new OnboardingEntity());

            onboarding.setUser(user);
            onboarding.setRole(role);
            onboarding.setProfilePhoto(teacherRequest.getProfilePhoto());
            onboarding.setFullName(teacherRequest.getName());
            onboarding.setBio(teacherRequest.getBio());
            onboarding.setSubject(teacherRequest.getSubject());
            onboarding.setTeachingLevel(teacherRequest.getTeachingLevel());
            onboarding.setHasCertificate(teacherRequest.getHasCertificate());
            onboarding.setCertificateUrl(teacherRequest.getCertificateUrl());
            onboarding.setTeachingVideoUrl(teacherRequest.getTeachingVideoUrl());
            onboarding.setClassType(teacherRequest.getClassType());
            onboarding.setFreeClassAmount(teacherRequest.getFreeClassAmount());
            onboarding.setWeeklySchedule(teacherRequest.getWeeklySchedule());
            onboarding.setFirstClassTitle(teacherRequest.getFirstClassTitle());
            onboarding.setFirstClassDescription(teacherRequest.getFirstClassDescription());
            onboarding.setCourseDurationDays(teacherRequest.getCourseDurationDays());
            onboarding.setBatchesPerDay(teacherRequest.getBatchesPerDay());
            onboarding.setBatchDurationMinutes(teacherRequest.getBatchDurationMinutes());
            onboarding.setMaxStudentsPerBatch(teacherRequest.getMaxStudentsPerBatch());
            onboarding.setIsCompleted(teacherRequest.getCompleteSetup());

            // NEW: Set timer fields for verification
            if (teacherRequest.getCompleteSetup()) {
                LocalDateTime now = LocalDateTime.now();
                onboarding.setTimerStartedAt(now);
                onboarding.setTimerExpiresAt(now.plusDays(2));
                onboarding.setCanCreatePaidClasses(false);
            }

            onboardingRepository.save(onboarding);

            // Update user role onboarding status if complete setup
            if (teacherRequest.getCompleteSetup()) {
                userRole.setIsOnboarded(true);
                userRoleRepository.save(userRole);

                // NEW: Initialize teacher verification process
                String submissionType = teacherRequest.getHasCertificate() ? "CERTIFICATE" : "VIDEO";
                String fileUrl = teacherRequest.getHasCertificate() ?
                        teacherRequest.getCertificateUrl() : teacherRequest.getTeachingVideoUrl();

                if (fileUrl != null && !fileUrl.trim().isEmpty()) {
                    teacherVerificationService.initializeVerification(user, submissionType, fileUrl);
                    log.info("Teacher verification initialized for user: {} with type: {}", user.getEmail(), submissionType);
                }
            }

            Map<String, Object> response = new HashMap<>();
            response.put("roleId", role.getRoleId());
            response.put("roleName", role.getRoleName());
            response.put("message", "Teacher onboarding submitted successfully");
            response.put("isCompleted", teacherRequest.getCompleteSetup());

            // NEW: Enhanced redirect logic
            if (teacherRequest.getCompleteSetup()) {
                response.put("redirectTo", "teacher-dashboard");
                response.put("verificationStarted", true);
                response.put("timerDays", 2);
            } else {
                response.put("redirectTo", "continue-onboarding");
                response.put("verificationStarted", false);
            }

            log.info("Teacher onboarding submitted for roleId: {} by user: {}", role.getRoleId(), user.getEmail());
            return ApiResponseDto.success("Teacher onboarding submitted successfully", response);

        } catch (Exception e) {
            log.error("Failed to process teacher onboarding for roleId: {}", role.getRoleId(), e);
            return ApiResponseDto.error("Invalid teacher onboarding data: " + e.getMessage());
        }
    }

    private ApiResponseDto<Map<String, Object>> handleStudentOnboarding(User user, RoleEntity role, UserRole userRole, Object request) {
        try {
            // Convert request to StudentOnboardingDto
            StudentOnboardingDto studentRequest;
            if (request instanceof StudentOnboardingDto) {
                studentRequest = (StudentOnboardingDto) request;
            } else {
                // Convert from generic object (e.g., LinkedHashMap from JSON)
                studentRequest = objectMapper.convertValue(request, StudentOnboardingDto.class);
            }

            // Create or update onboarding data
            OnboardingEntity onboarding = onboardingRepository.findByUserAndRole(user, role)
                    .orElse(new OnboardingEntity());

            onboarding.setUser(user);
            onboarding.setRole(role);
            onboarding.setProfilePhoto(studentRequest.getProfilePhoto());
            onboarding.setFullName(studentRequest.getName());

            // Convert List<String> to comma-separated String
            String interestedSubjectsStr = studentRequest.getInterestedSubjects() != null ?
                    String.join(",", studentRequest.getInterestedSubjects()) : null;
            onboarding.setInterestedSubjects(interestedSubjectsStr);

            onboarding.setLearningPreference(studentRequest.getLearningPreference());
            onboarding.setPreferredLearningType(studentRequest.getPreferredLearningType());
            onboarding.setReadyToStart(studentRequest.getReadyToStart());
            onboarding.setIsCompleted(studentRequest.getCompleteSetup());

            onboardingRepository.save(onboarding);

            // Update user role onboarding status if complete setup
            if (studentRequest.getCompleteSetup()) {
                userRole.setIsOnboarded(true);
                userRoleRepository.save(userRole);
            }

            Map<String, Object> response = new HashMap<>();
            response.put("roleId", role.getRoleId());
            response.put("roleName", role.getRoleName());
            response.put("message", "Student onboarding submitted successfully");
            response.put("isCompleted", studentRequest.getCompleteSetup());

            String redirectTo;
            if (studentRequest.getCompleteSetup()) {
                redirectTo = "FIND_CLASSES".equals(studentRequest.getReadyToStart()) ?
                        "class-discovery" : "student-dashboard";
            } else {
                redirectTo = "continue-onboarding";
            }
            response.put("redirectTo", redirectTo);

            log.info("Student onboarding submitted for roleId: {} by user: {}", role.getRoleId(), user.getEmail());
            return ApiResponseDto.success("Student onboarding submitted successfully", response);

        } catch (Exception e) {
            log.error("Failed to process student onboarding for roleId: {}", role.getRoleId(), e);
            return ApiResponseDto.error("Invalid student onboarding data: " + e.getMessage());
        }
    }

    private Map<String, Object> convertOnboardingToMap(OnboardingEntity onboarding) {
        Map<String, Object> map = new HashMap<>();
        map.put("id", onboarding.getId());
        map.put("profilePhoto", onboarding.getProfilePhoto());
        map.put("fullName", onboarding.getFullName());
        map.put("bio", onboarding.getBio());
        map.put("subject", onboarding.getSubject());
        map.put("interestedSubjects", onboarding.getInterestedSubjects());
        map.put("teachingLevel", onboarding.getTeachingLevel());
        map.put("learningPreference", onboarding.getLearningPreference());
        map.put("hasCertificate", onboarding.getHasCertificate());
        map.put("certificateUrl", onboarding.getCertificateUrl());
        map.put("teachingVideoUrl", onboarding.getTeachingVideoUrl());
        map.put("classType", onboarding.getClassType());
        map.put("preferredLearningType", onboarding.getPreferredLearningType());
        map.put("freeClassAmount", onboarding.getFreeClassAmount());
        map.put("weeklySchedule", onboarding.getWeeklySchedule());
        map.put("firstClassTitle", onboarding.getFirstClassTitle());
        map.put("firstClassDescription", onboarding.getFirstClassDescription());
        map.put("courseDurationDays", onboarding.getCourseDurationDays());
        map.put("batchesPerDay", onboarding.getBatchesPerDay());
        map.put("batchDurationMinutes", onboarding.getBatchDurationMinutes());
        map.put("maxStudentsPerBatch", onboarding.getMaxStudentsPerBatch());
        map.put("readyToStart", onboarding.getReadyToStart());
        map.put("isCompleted", onboarding.getIsCompleted());
        map.put("createdAt", onboarding.getCreatedAt());
        map.put("updatedAt", onboarding.getUpdatedAt());
        return map;
    }

    // ===== LEGACY METHODS (Keep for backward compatibility) =====

    @Deprecated
    public ApiResponseDto<Map<String, Object>> submitTeacherOnboarding(TeacherOnboardingDto request) {
        // This method can still work by finding the TEACHER role and delegating
        RoleEntity teacherRole = roleService.findByRoleName("TEACHER");
        return submitOnboardingByRoleId(teacherRole.getRoleId(), request);
    }

    @Deprecated
    public ApiResponseDto<Map<String, Object>> submitStudentOnboarding(StudentOnboardingDto request) {
        // This method can still work by finding the STUDENT role and delegating
        RoleEntity studentRole = roleService.findByRoleName("STUDENT");
        return submitOnboardingByRoleId(studentRole.getRoleId(), request);
    }

    public ApiResponseDto<Map<String, Object>> getClassDiscovery(ClassDiscoveryDto request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        // Here you would typically query your classes/courses database
        // For now, returning mock data structure
        Map<String, Object> response = new HashMap<>();
        response.put("searchCriteria", Map.of(
                "subjects", request.getInterestedSubjects(),
                "level", request.getLearningLevel(),
                "type", request.getPreferredLearningType()
        ));
        response.put("availableClasses", "Query your classes database here based on criteria");
        response.put("message", "Class discovery completed. Redirecting to browse classes.");

        log.info("Class discovery request processed for user: {}", email);
        return ApiResponseDto.success("Class discovery completed", response);
    }

    @Deprecated
    public ApiResponseDto<OnboardingEntity> getOnboardingData(String roleName) {
        // This method can still work by finding the role and delegating
        RoleEntity role = roleService.findByRoleName(roleName.toUpperCase());
        ApiResponseDto<Map<String, Object>> response = getOnboardingDataByRoleId(role.getRoleId());

        // Convert back to legacy format
        if (response.isSuccess() && response.getData() != null) {
            try {
                OnboardingEntity entity = objectMapper.convertValue(response.getData(), OnboardingEntity.class);
                return ApiResponseDto.success(response.getMessage(), entity);
            } catch (Exception e) {
                return ApiResponseDto.success("No onboarding data found", null);
            }
        }
        return ApiResponseDto.success("No onboarding data found", null);
    }
}