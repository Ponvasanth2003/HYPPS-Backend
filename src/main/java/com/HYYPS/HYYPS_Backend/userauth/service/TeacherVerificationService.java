package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.entity.*;
import com.HYYPS.HYYPS_Backend.userauth.enums.SubmissionType;
import com.HYYPS.HYYPS_Backend.userauth.enums.VerificationStatus;
import com.HYYPS.HYYPS_Backend.userauth.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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
public class TeacherVerificationService {

    private final TeacherVerificationRepository teacherVerificationRepository;
    private final UserRepository userRepository;
    private final RoleService roleService;
    private final EmailService emailService;
    private final CacheService cacheService;
    private final KycService kycService; // Added missing dependency

    private static final int VERIFICATION_TIMER_DAYS = 2;

    @Transactional
    public ApiResponseDto<Map<String, Object>> initializeVerification(User user, String submissionType, String fileUrl) {
        try {
            // Check if verification already exists
            TeacherVerificationEntity existingVerification = teacherVerificationRepository.findByUser(user).orElse(null);

            LocalDateTime now = LocalDateTime.now();
            LocalDateTime timerExpires = now.plusDays(VERIFICATION_TIMER_DAYS);

            if (existingVerification != null) {
                // Update existing verification
                existingVerification.setSubmissionType(SubmissionType.valueOf(submissionType.toUpperCase()));
                existingVerification.setFileUrl(fileUrl);
                existingVerification.setProfileVerificationStatus(VerificationStatus.PENDING);
                existingVerification.setRejectionReason(null);
                existingVerification.setVerifiedAt(null);
                existingVerification.setVerifiedBy(null);
                existingVerification.setRetryCount(existingVerification.getRetryCount() + 1);
            } else {
                // Create new verification
                existingVerification = new TeacherVerificationEntity();
                existingVerification.setUser(user);
                existingVerification.setSubmissionType(SubmissionType.valueOf(submissionType.toUpperCase()));
                existingVerification.setFileUrl(fileUrl);
                existingVerification.setTimerStartedAt(now);
                existingVerification.setTimerExpiresAt(timerExpires);
                existingVerification.setRetryCount(0);
            }

            teacherVerificationRepository.save(existingVerification);

            Map<String, Object> response = new HashMap<>();
            response.put("verificationId", existingVerification.getId());
            response.put("timerStartedAt", existingVerification.getTimerStartedAt());
            response.put("timerExpiresAt", existingVerification.getTimerExpiresAt());
            response.put("submissionType", existingVerification.getSubmissionType());

            log.info("Teacher verification initialized for user: {}, type: {}", user.getEmail(), submissionType);
            return ApiResponseDto.success("Verification initialized successfully", response);

        } catch (Exception e) {
            log.error("Failed to initialize verification for user: {}", user.getEmail(), e);
            return ApiResponseDto.error("Failed to initialize verification");
        }
    }

    @Cacheable(value = "teacherDashboard", key = "#userEmail")
    public ApiResponseDto<TeacherDashboardDto> getDashboardData(String userEmail) {
        try {
            User user = userRepository.findActiveUserByEmail(userEmail)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            TeacherVerificationEntity verification = teacherVerificationRepository.findByUser(user).orElse(null);

            TeacherDashboardDto dashboard = new TeacherDashboardDto();

            // Profile Verification Step
            Map<String, Object> profileStep = createProfileVerificationStep(verification);
            dashboard.setProfileVerification(profileStep);

            // KYC Verification Step
            Map<String, Object> kycStep = createKycVerificationStep(user, verification);
            dashboard.setKycVerification(kycStep);

            // Timer Information
            Map<String, Object> timerInfo = createTimerInfo(verification);
            dashboard.setTimerInfo(timerInfo);

            // Can create paid classes check
            boolean canCreatePaidClasses = checkCanCreatePaidClasses(user, verification);
            dashboard.setCanCreatePaidClasses(canCreatePaidClasses);

            // Next steps
            dashboard.setNextSteps(determineNextSteps(verification, canCreatePaidClasses));

            return ApiResponseDto.success("Dashboard data retrieved successfully", dashboard);

        } catch (Exception e) {
            log.error("Failed to retrieve dashboard data for user: {}", userEmail, e);
            return ApiResponseDto.error("Failed to retrieve dashboard data");
        }
    }

    @Transactional
    @CacheEvict(value = {"teacherDashboard", "adminVerifications"}, allEntries = true)
    public ApiResponseDto<Map<String, Object>> reuploadFile(String userEmail, FileReuploadDto request) {
        try {
            User user = userRepository.findActiveUserByEmail(userEmail)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            TeacherVerificationEntity verification = teacherVerificationRepository.findByUser(user)
                    .orElseThrow(() -> new RuntimeException("Verification record not found"));

            // Only allow reupload if rejected or second chance allowed
            if (verification.getProfileVerificationStatus() != VerificationStatus.REJECTED &&
                    !verification.getSecondChanceAllowed()) {
                return ApiResponseDto.error("File reupload not allowed at this time");
            }

            // Update verification
            verification.setFileUrl(request.getFileUrl());
            verification.setProfileVerificationStatus(VerificationStatus.PENDING);
            verification.setRejectionReason(null);
            verification.setVerifiedAt(null);
            verification.setVerifiedBy(null);
            verification.setSecondChanceAllowed(false);
            verification.setRetryCount(verification.getRetryCount() + 1);

            teacherVerificationRepository.save(verification);

            Map<String, Object> response = new HashMap<>();
            response.put("message", "File uploaded successfully. Pending admin review.");
            response.put("retryCount", verification.getRetryCount());
            response.put("status", "PENDING");

            log.info("Teacher {} reuploaded file, attempt: {}", userEmail, verification.getRetryCount());
            return ApiResponseDto.success("File reuploaded successfully", response);

        } catch (Exception e) {
            log.error("Failed to reupload file for user: {}", userEmail, e);
            return ApiResponseDto.error("Failed to reupload file");
        }
    }

    // Admin Methods

    @Cacheable(value = "adminVerifications", key = "'pending:' + #page + ':' + #size")
    public ApiResponseDto<Map<String, Object>> getPendingVerifications(int page, int size) {
        try {
            Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").ascending());
            Page<TeacherVerificationEntity> verificationPage =
                    teacherVerificationRepository.findByProfileVerificationStatus(VerificationStatus.PENDING, pageable);

            List<TeacherVerificationDto> verifications = verificationPage.getContent().stream()
                    .map(this::mapToDto)
                    .collect(Collectors.toList());

            Map<String, Object> response = new HashMap<>();
            response.put("verifications", verifications);
            response.put("pagination", createPaginationMap(verificationPage));

            return ApiResponseDto.success("Pending verifications retrieved successfully", response);

        } catch (Exception e) {
            log.error("Failed to retrieve pending verifications", e);
            return ApiResponseDto.error("Failed to retrieve pending verifications");
        }
    }

    @Transactional
    @CacheEvict(value = {"teacherDashboard", "adminVerifications"}, allEntries = true)
    public ApiResponseDto<Map<String, Object>> verifyProfile(Long verificationId, ProfileVerificationRequestDto request) {
        try {
            TeacherVerificationEntity verification = teacherVerificationRepository.findById(verificationId)
                    .orElseThrow(() -> new RuntimeException("Verification not found"));

            User admin = getCurrentAuthenticatedUser();
            LocalDateTime now = LocalDateTime.now();

            if ("VERIFY".equals(request.getAction())) {
                verification.setProfileVerificationStatus(VerificationStatus.VERIFIED);
                verification.setVerifiedAt(now);
                verification.setVerifiedBy(admin);
                verification.setRejectionReason(null);

                // Send email notification for KYC upload
                emailService.sendProfileVerifiedEmail(
                        verification.getUser().getEmail(),
                        verification.getUser().getName()
                );

                log.info("Profile verified for user: {} by admin: {}",
                        verification.getUser().getEmail(), admin.getEmail());

            } else if ("REJECT".equals(request.getAction())) {
                verification.setProfileVerificationStatus(VerificationStatus.REJECTED);
                verification.setRejectionReason(request.getRejectionReason());
                verification.setSecondChanceAllowed(true);
                verification.setVerifiedAt(null);
                verification.setVerifiedBy(admin);

                // Send rejection email
                emailService.sendProfileRejectedEmail(
                        verification.getUser().getEmail(),
                        verification.getUser().getName(),
                        request.getRejectionReason()
                );

                log.info("Profile rejected for user: {} by admin: {}, reason: {}",
                        verification.getUser().getEmail(), admin.getEmail(), request.getRejectionReason());
            }

            teacherVerificationRepository.save(verification);

            Map<String, Object> response = new HashMap<>();
            response.put("verificationId", verificationId);
            response.put("action", request.getAction());
            response.put("status", verification.getProfileVerificationStatus());

            return ApiResponseDto.success("Profile verification updated successfully", response);

        } catch (Exception e) {
            log.error("Failed to verify profile for verificationId: {}", verificationId, e);
            return ApiResponseDto.error("Failed to verify profile");
        }
    }

    // Helper Methods

    private Map<String, Object> createProfileVerificationStep(TeacherVerificationEntity verification) {
        Map<String, Object> step = new HashMap<>();

        if (verification == null) {
            step.put("status", "NOT_SUBMITTED");
            step.put("title", "Profile Verification Not Started");
            step.put("description", "Please complete your onboarding first");
            step.put("canReupload", false);
            return step;
        }

        step.put("status", verification.getProfileVerificationStatus().toString());
        step.put("submissionType", verification.getSubmissionType().toString());
        step.put("fileUrl", verification.getFileUrl());
        step.put("retryCount", verification.getRetryCount());

        switch (verification.getProfileVerificationStatus()) {
            case PENDING:
                step.put("title", "Profile Verification Pending");
                step.put("description", "Your " + verification.getSubmissionType().toString().toLowerCase() +
                        " is under admin review");
                step.put("canReupload", false);
                break;
            case VERIFIED:
                step.put("title", "Profile Verification Complete");
                step.put("description", "Your profile has been verified successfully");
                step.put("verifiedAt", verification.getVerifiedAt());
                step.put("canReupload", false);
                break;
            case REJECTED:
                step.put("title", "Profile Verification Rejected");
                step.put("description", verification.getRejectionReason());
                step.put("canReupload", verification.getSecondChanceAllowed());
                break;
        }

        return step;
    }

    private Map<String, Object> createKycVerificationStep(User user, TeacherVerificationEntity verification) {
        Map<String, Object> step = new HashMap<>();

        // KYC step is only available after profile verification
        if (verification == null || verification.getProfileVerificationStatus() != VerificationStatus.VERIFIED) {
            step.put("status", "LOCKED");
            step.put("title", "KYC Verification Locked");
            step.put("description", "Complete profile verification first");
            step.put("canUpload", false);
            return step;
        }

        // Check KYC submission status
        KycSubmissionEntity kycSubmission = kycService.getKycSubmission(user);

        if (kycSubmission == null) {
            step.put("status", "NOT_SUBMITTED");
            step.put("title", "KYC Documents Required");
            step.put("description", "Upload your government ID, bank proof, and optional selfie");
            step.put("canUpload", true);
        } else {
            step.put("status", kycSubmission.getKycStatus().toString());
            step.put("submittedAt", kycSubmission.getCreatedAt());

            switch (kycSubmission.getKycStatus()) {
                case PENDING:
                    step.put("title", "KYC Under Review");
                    step.put("description", "Your KYC documents are being reviewed by admin");
                    step.put("canUpload", false);
                    break;
                case VERIFIED:
                    step.put("title", "KYC Verification Complete");
                    step.put("description", "Your KYC documents have been verified");
                    step.put("verifiedAt", kycSubmission.getVerifiedAt());
                    step.put("canUpload", false);
                    break;
                case REJECTED:
                    step.put("title", "KYC Documents Rejected");
                    step.put("description", kycSubmission.getRejectionReason());
                    step.put("canUpload", true);
                    break;
            }
        }

        return step;
    }

    private Map<String, Object> createTimerInfo(TeacherVerificationEntity verification) {
        Map<String, Object> timer = new HashMap<>();

        if (verification == null) {
            timer.put("isActive", false);
            timer.put("message", "Timer will start after profile submission");
            return timer;
        }

        LocalDateTime now = LocalDateTime.now();
        Duration remaining = Duration.between(now, verification.getTimerExpiresAt());

        timer.put("startedAt", verification.getTimerStartedAt());
        timer.put("expiresAt", verification.getTimerExpiresAt());
        timer.put("isActive", remaining.toSeconds() > 0);
        timer.put("remainingDays", Math.max(0, remaining.toDays()));
        timer.put("remainingHours", Math.max(0, remaining.toHours() % 24));
        timer.put("remainingMinutes", Math.max(0, remaining.toMinutes() % 60));

        if (remaining.toSeconds() <= 0) {
            timer.put("message", "Verification timer has expired");
        } else {
            timer.put("message", String.format("%.1f days remaining", remaining.toHours() / 24.0));
        }

        return timer;
    }

    private boolean checkCanCreatePaidClasses(User user, TeacherVerificationEntity verification) {
        if (verification == null || verification.getProfileVerificationStatus() != VerificationStatus.VERIFIED) {
            return false;
        }

        // Check if KYC is verified
        KycSubmissionEntity kyc = kycService.getKycSubmission(user);
        if (kyc == null || kyc.getKycStatus() != VerificationStatus.VERIFIED) {
            return false;
        }

        // Check if timer has expired
        LocalDateTime now = LocalDateTime.now();
        return now.isAfter(verification.getTimerExpiresAt());
    }

    private String determineNextSteps(TeacherVerificationEntity verification, boolean canCreatePaidClasses) {
        if (verification == null) {
            return "Complete your teacher onboarding to start verification process";
        }

        if (canCreatePaidClasses) {
            return "All verification complete! You can now create paid classes";
        }

        if (verification.getProfileVerificationStatus() == VerificationStatus.REJECTED) {
            return "Upload a new video to continue verification process";
        }

        if (verification.getProfileVerificationStatus() == VerificationStatus.PENDING) {
            return "Wait for admin to review your profile submission";
        }

        if (verification.getProfileVerificationStatus() == VerificationStatus.VERIFIED) {
            KycSubmissionEntity kyc = kycService.getKycSubmission(verification.getUser());
            if (kyc == null) {
                return "Upload your KYC documents to proceed";
            } else if (kyc.getKycStatus() == VerificationStatus.PENDING) {
                return "Wait for admin to review your KYC documents";
            } else if (kyc.getKycStatus() == VerificationStatus.REJECTED) {
                return "Re-upload your KYC documents with corrections";
            }
        }

        return "Continue with verification process";
    }

    private TeacherVerificationDto mapToDto(TeacherVerificationEntity verification) {
        TeacherVerificationDto dto = new TeacherVerificationDto();
        dto.setId(verification.getId());
        dto.setUserId(verification.getUser().getId());
        dto.setTeacherName(verification.getUser().getName());
        dto.setTeacherEmail(verification.getUser().getEmail());
        dto.setSubmissionType(verification.getSubmissionType().toString());
        dto.setFileUrl(verification.getFileUrl());
        dto.setProfileVerificationStatus(verification.getProfileVerificationStatus().toString());
        dto.setRejectionReason(verification.getRejectionReason());
        dto.setVerifiedAt(verification.getVerifiedAt() != null ? verification.getVerifiedAt().toString() : null);
        dto.setVerifiedByName(verification.getVerifiedBy() != null ? verification.getVerifiedBy().getName() : null);
        dto.setTimerStartedAt(verification.getTimerStartedAt().toString());
        dto.setTimerExpiresAt(verification.getTimerExpiresAt().toString());

        LocalDateTime now = LocalDateTime.now();
        Duration remaining = Duration.between(now, verification.getTimerExpiresAt());
        dto.setDaysRemaining(Math.max(0, remaining.toDays()));

        dto.setSecondChanceAllowed(verification.getSecondChanceAllowed());
        dto.setRetryCount(verification.getRetryCount());
        dto.setCreatedAt(verification.getCreatedAt().toString());

        return dto;
    }

    private User getCurrentAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();
        return userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("Admin user not found"));
    }

    private Map<String, Object> createPaginationMap(Page<?> page) {
        Map<String, Object> pagination = new HashMap<>();
        pagination.put("page", page.getNumber());
        pagination.put("size", page.getSize());
        pagination.put("totalElements", page.getTotalElements());
        pagination.put("totalPages", page.getTotalPages());
        pagination.put("isFirst", page.isFirst());
        pagination.put("isLast", page.isLast());
        return pagination;
    }
}