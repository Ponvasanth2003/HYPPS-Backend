package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.entity.SecurityEvent;
import com.HYYPS.HYYPS_Backend.userauth.entity.User;
import com.HYYPS.HYYPS_Backend.userauth.repository.SecurityEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class VerificationAuditService {

    private final SecurityEventRepository securityEventRepository;

    @Transactional
    public void logVerificationEvent(String eventType, User user, String details, String clientIp) {
        try {
            SecurityEvent event = new SecurityEvent();
            event.setEventType(eventType);
            event.setUserEmail(user.getEmail());
            event.setClientIp(clientIp);
            event.setDetails(details);
            event.setSeverity("INFO");
            event.setTimestamp(LocalDateTime.now());

            securityEventRepository.save(event);
            log.debug("Verification event logged: {} for user: {}", eventType, user.getEmail());

        } catch (Exception e) {
            log.error("Failed to log verification event for user: {}", user.getEmail(), e);
        }
    }

    public void logProfileVerification(User teacher, User admin, String action, String reason) {
        String details = String.format("Profile %s by admin %s. Reason: %s",
                action.toLowerCase(), admin.getEmail(), reason != null ? reason : "N/A");
        logVerificationEvent("PROFILE_VERIFICATION", teacher, details, "admin-action");
    }

    public void logKycVerification(User teacher, User admin, String action, String reason) {
        String details = String.format("KYC %s by admin %s. Reason: %s",
                action.toLowerCase(), admin.getEmail(), reason != null ? reason : "N/A");
        logVerificationEvent("KYC_VERIFICATION", teacher, details, "admin-action");
    }

    public void logFileReupload(User teacher, int retryCount) {
        String details = String.format("File reuploaded (attempt %d)", retryCount);
        logVerificationEvent("FILE_REUPLOAD", teacher, details, "teacher-action");
    }
}