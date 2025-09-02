package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.entity.*;
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

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class KycService {

    private final KycSubmissionRepository kycSubmissionRepository;
    private final TeacherVerificationRepository teacherVerificationRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final RateLimitService rateLimitService;

    @Transactional
    @CacheEvict(value = {"teacherDashboard", "adminKyc"}, allEntries = true)
    public ApiResponseDto<Map<String, Object>> uploadKycDocuments(String userEmail, KycUploadDto request) {
        try {
            User user = userRepository.findActiveUserByEmail(userEmail)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Check if profile is verified
            TeacherVerificationEntity verification = teacherVerificationRepository.findByUser(user)
                    .orElseThrow(() -> new RuntimeException("Profile verification not found"));

            if (verification.getProfileVerificationStatus() != VerificationStatus.VERIFIED) {
                return ApiResponseDto.error("Profile must be verified before uploading KYC documents");
            }

            // Rate limiting for KYC uploads
            String rateLimitKey = "kyc_upload:" + userEmail;
            rateLimitService.checkRateLimit(rateLimitKey, 60, 5, "Too many KYC upload attempts. Please try again later.");

            // Create or update KYC submission
            KycSubmissionEntity kycSubmission = kycSubmissionRepository.findByUser(user)
                    .orElse(new KycSubmissionEntity());

            kycSubmission.setUser(user);
            kycSubmission.setGovtIdUrl(request.getGovtIdUrl());
            kycSubmission.setBankProofUrl(request.getBankProofUrl());
            kycSubmission.setSelfieWithIdUrl(request.getSelfieWithIdUrl());
            kycSubmission.setKycStatus(VerificationStatus.PENDING);
            kycSubmission.setRejectionReason(null);
            kycSubmission.setVerifiedAt(null);
            kycSubmission.setVerifiedBy(null);

            kycSubmissionRepository.save(kycSubmission);

            Map<String, Object> response = new HashMap<>();
            response.put("kycId", kycSubmission.getId());
            response.put("status", "PENDING");
            response.put("message", "KYC documents uploaded successfully. Pending admin review.");

            log.info("KYC documents uploaded by user: {}", userEmail);
            return ApiResponseDto.success("KYC documents uploaded successfully", response);

        } catch (Exception e) {
            log.error("Failed to upload KYC documents for user: {}", userEmail, e);
            return ApiResponseDto.error("Failed to upload KYC documents: " + e.getMessage());
        }
    }

    @Cacheable(value = "adminKyc", key = "'pending:' + #page + ':' + #size")
    public ApiResponseDto<Map<String, Object>> getPendingKycSubmissions(int page, int size) {
        try {
            Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").ascending());
            Page<KycSubmissionEntity> kycPage =
                    kycSubmissionRepository.findByKycStatus(VerificationStatus.PENDING, pageable);

            List<Map<String, Object>> submissions = kycPage.getContent().stream()
                    .map(this::mapKycToMap)
                    .collect(Collectors.toList());

            Map<String, Object> response = new HashMap<>();
            response.put("kycSubmissions", submissions);
            response.put("pagination", createPaginationMap(kycPage));

            return ApiResponseDto.success("Pending KYC submissions retrieved successfully", response);

        } catch (Exception e) {
            log.error("Failed to retrieve pending KYC submissions", e);
            return ApiResponseDto.error("Failed to retrieve pending KYC submissions");
        }
    }

    @Transactional
    @CacheEvict(value = {"teacherDashboard", "adminKyc"}, allEntries = true)
    public ApiResponseDto<Map<String, Object>> verifyKyc(Long kycId, KycVerificationRequestDto request) {
        try {
            KycSubmissionEntity kycSubmission = kycSubmissionRepository.findById(kycId)
                    .orElseThrow(() -> new RuntimeException("KYC submission not found"));

            User admin = getCurrentAuthenticatedUser();
            LocalDateTime now = LocalDateTime.now();

            if ("VERIFY".equals(request.getAction())) {
                kycSubmission.setKycStatus(VerificationStatus.VERIFIED);
                kycSubmission.setVerifiedAt(now);
                kycSubmission.setVerifiedBy(admin);
                kycSubmission.setRejectionReason(null);

                // Check if teacher can now create paid classes
                boolean canCreatePaidClasses = checkCanCreatePaidClasses(kycSubmission.getUser());

                // Send verification complete email
                emailService.sendKycVerifiedEmail(
                        kycSubmission.getUser().getEmail(),
                        kycSubmission.getUser().getName(),
                        canCreatePaidClasses
                );

                log.info("KYC verified for user: {} by admin: {}",
                        kycSubmission.getUser().getEmail(), admin.getEmail());

            } else if ("REJECT".equals(request.getAction())) {
                kycSubmission.setKycStatus(VerificationStatus.REJECTED);
                kycSubmission.setRejectionReason(request.getRejectionReason());
                kycSubmission.setVerifiedAt(null);
                kycSubmission.setVerifiedBy(admin);

                // Send rejection email
                emailService.sendKycRejectedEmail(
                        kycSubmission.getUser().getEmail(),
                        kycSubmission.getUser().getName(),
                        request.getRejectionReason()
                );

                log.info("KYC rejected for user: {} by admin: {}, reason: {}",
                        kycSubmission.getUser().getEmail(), admin.getEmail(), request.getRejectionReason());
            }

            kycSubmissionRepository.save(kycSubmission);

            Map<String, Object> response = new HashMap<>();
            response.put("kycId", kycId);
            response.put("action", request.getAction());
            response.put("status", kycSubmission.getKycStatus());

            return ApiResponseDto.success("KYC verification updated successfully", response);

        } catch (Exception e) {
            log.error("Failed to verify KYC for kycId: {}", kycId, e);
            return ApiResponseDto.error("Failed to verify KYC");
        }
    }

    public KycSubmissionEntity getKycSubmission(User user) {
        return kycSubmissionRepository.findByUser(user).orElse(null);
    }

    private boolean checkCanCreatePaidClasses(User user) {
        TeacherVerificationEntity verification = teacherVerificationRepository.findByUser(user).orElse(null);
        if (verification == null || verification.getProfileVerificationStatus() != VerificationStatus.VERIFIED) {
            return false;
        }

        KycSubmissionEntity kyc = getKycSubmission(user);
        if (kyc == null || kyc.getKycStatus() != VerificationStatus.VERIFIED) {
            return false;
        }

        // Check if timer has expired
        LocalDateTime now = LocalDateTime.now();
        return now.isAfter(verification.getTimerExpiresAt());
    }

    private Map<String, Object> mapKycToMap(KycSubmissionEntity kyc) {
        Map<String, Object> map = new HashMap<>();
        map.put("id", kyc.getId());
        map.put("userId", kyc.getUser().getId());
        map.put("teacherName", kyc.getUser().getName());
        map.put("teacherEmail", kyc.getUser().getEmail());
        map.put("govtIdUrl", kyc.getGovtIdUrl());
        map.put("bankProofUrl", kyc.getBankProofUrl());
        map.put("selfieWithIdUrl", kyc.getSelfieWithIdUrl());
        map.put("kycStatus", kyc.getKycStatus().toString());
        map.put("rejectionReason", kyc.getRejectionReason());
        map.put("verifiedAt", kyc.getVerifiedAt());
        map.put("verifiedByName", kyc.getVerifiedBy() != null ? kyc.getVerifiedBy().getName() : null);
        map.put("submittedAt", kyc.getCreatedAt());
        return map;
    }

    private User getCurrentAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();
        return userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
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