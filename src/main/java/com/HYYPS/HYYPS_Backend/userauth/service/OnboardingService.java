package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.entity.*;
import com.HYYPS.HYYPS_Backend.userauth.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

    public ApiResponseDto<Map<String, Object>> submitTeacherOnboarding(TeacherOnboardingDto request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        RoleEntity teacherRole = roleService.findByRoleName("TEACHER");

        // Check if user has teacher role
        UserRole userRole = userRoleRepository.findByUserAndRole(user, teacherRole)
                .orElseThrow(() -> new RuntimeException("Teacher role not found for user"));

        // Create or update onboarding data
        OnboardingEntity onboarding = onboardingRepository.findByUserAndRole(user, teacherRole)
                .orElse(new OnboardingEntity());

        onboarding.setUser(user);
        onboarding.setRole(teacherRole);
        onboarding.setProfilePhoto(request.getProfilePhoto());
        onboarding.setFullName(request.getName());
        onboarding.setBio(request.getBio());
        onboarding.setSubject(request.getSubject());
        onboarding.setTeachingLevel(request.getTeachingLevel());
        onboarding.setHasCertificate(request.getHasCertificate());
      //  onboarding.setCertificateUrl(request.getCertificateUrl());     -------vasanth bending for AWS
        onboarding.setTeachingVideoUrl(request.getTeachingVideoUrl());
        onboarding.setClassType(request.getClassType());
        onboarding.setFreeClassAmount(request.getFreeClassAmount());
        onboarding.setWeeklySchedule(request.getWeeklySchedule());
        onboarding.setFirstClassTitle(request.getFirstClassTitle());
        onboarding.setFirstClassDescription(request.getFirstClassDescription());
        onboarding.setCourseDurationDays(request.getCourseDurationDays());
        onboarding.setBatchesPerDay(request.getBatchesPerDay());
        onboarding.setBatchDurationMinutes(request.getBatchDurationMinutes());
        onboarding.setMaxStudentsPerBatch(request.getMaxStudentsPerBatch());
        onboarding.setIsCompleted(request.getCompleteSetup());

        onboardingRepository.save(onboarding);

        // Update user role onboarding status if complete setup
        if (request.getCompleteSetup()) {
            userRole.setIsOnboarded(true);
            userRoleRepository.save(userRole);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Teacher onboarding submitted successfully");
        response.put("isCompleted", request.getCompleteSetup());
        response.put("redirectTo", request.getCompleteSetup() ? "teacher-dashboard" : "continue-onboarding");

        log.info("Teacher onboarding submitted for user: {}", email);
        return ApiResponseDto.success("Teacher onboarding submitted successfully", response);
    }

    public ApiResponseDto<Map<String, Object>> submitStudentOnboarding(StudentOnboardingDto request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        RoleEntity studentRole = roleService.findByRoleName("STUDENT");

        // Check if user has student role
        UserRole userRole = userRoleRepository.findByUserAndRole(user, studentRole)
                .orElseThrow(() -> new RuntimeException("Student role not found for user"));

        // Create or update onboarding data
        OnboardingEntity onboarding = onboardingRepository.findByUserAndRole(user, studentRole)
                .orElse(new OnboardingEntity());

        onboarding.setUser(user);
        onboarding.setRole(studentRole);
        onboarding.setProfilePhoto(request.getProfilePhoto());
        onboarding.setFullName(request.getName());
        onboarding.setInterestedSubjects(request.getInterestedSubjects());
        onboarding.setLearningPreference(request.getLearningPreference());
        onboarding.setPreferredLearningType(request.getPreferredLearningType());
        onboarding.setReadyToStart(request.getReadyToStart());
        onboarding.setIsCompleted(request.getCompleteSetup());

        onboardingRepository.save(onboarding);

        // Update user role onboarding status if complete setup
        if (request.getCompleteSetup()) {
            userRole.setIsOnboarded(true);
            userRoleRepository.save(userRole);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Student onboarding submitted successfully");
        response.put("isCompleted", request.getCompleteSetup());

        String redirectTo;
        if (request.getCompleteSetup()) {
            redirectTo = "FIND_CLASSES".equals(request.getReadyToStart()) ?
                    "class-discovery" : "student-dashboard";
        } else {
            redirectTo = "continue-onboarding";
        }
        response.put("redirectTo", redirectTo);

        log.info("Student onboarding submitted for user: {}", email);
        return ApiResponseDto.success("Student onboarding submitted successfully", response);
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

    public ApiResponseDto<OnboardingEntity> getOnboardingData(String roleName) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        RoleEntity role = roleService.findByRoleName(roleName.toUpperCase());

        OnboardingEntity onboarding = onboardingRepository.findByUserAndRole(user, role)
                .orElse(null);

        String message = onboarding != null ?
                "Onboarding data retrieved successfully" :
                "No onboarding data found";

        return ApiResponseDto.success(message, onboarding);
    }
}