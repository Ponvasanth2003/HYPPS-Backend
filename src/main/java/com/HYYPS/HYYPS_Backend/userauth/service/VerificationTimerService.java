package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.entity.TeacherVerificationEntity;
import com.HYYPS.HYYPS_Backend.userauth.enums.VerificationStatus;
import com.HYYPS.HYYPS_Backend.userauth.repository.TeacherVerificationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class VerificationTimerService {

    private final TeacherVerificationRepository teacherVerificationRepository;
    private final EmailService emailService;

    @Scheduled(fixedRate = 3600000) // Run every hour
    @Transactional
    @CacheEvict(value = {"teacherDashboard", "adminVerifications"}, allEntries = true)
    public void processExpiredVerifications() {
        log.info("Processing expired teacher verifications...");

        LocalDateTime now = LocalDateTime.now();
        List<TeacherVerificationEntity> expiredVerifications =
                teacherVerificationRepository.findExpiredPendingVerifications(now);

        for (TeacherVerificationEntity verification : expiredVerifications) {
            try {
                // Auto-reject expired verifications
                verification.setProfileVerificationStatus(VerificationStatus.REJECTED);
                verification.setRejectionReason("Verification expired after 2 days without admin review");
                verification.setSecondChanceAllowed(true);

                teacherVerificationRepository.save(verification);

                // Send expiration email
                emailService.sendVerificationExpiredEmail(
                        verification.getUser().getEmail(),
                        verification.getUser().getName()
                );

                log.info("Verification expired for user: {}", verification.getUser().getEmail());

            } catch (Exception e) {
                log.error("Failed to process expired verification for user: {}",
                        verification.getUser().getEmail(), e);
            }
        }

        log.info("Processed {} expired verifications", expiredVerifications.size());
    }

    @Scheduled(cron = "0 0 9 * * *") // Daily at 9 AM
    public void sendVerificationReminders() {
        log.info("Sending verification reminders...");

        // Send reminders to teachers with pending verifications expiring in 24 hours
        LocalDateTime tomorrow = LocalDateTime.now().plusDays(1);
        LocalDateTime dayAfterTomorrow = LocalDateTime.now().plusDays(2);

        List<TeacherVerificationEntity> expiringVerifications =
                teacherVerificationRepository.findByTimerExpiresAtBetweenAndProfileVerificationStatus(
                        tomorrow, dayAfterTomorrow, VerificationStatus.PENDING);

        for (TeacherVerificationEntity verification : expiringVerifications) {
            try {
                emailService.sendVerificationReminderEmail(
                        verification.getUser().getEmail(),
                        verification.getUser().getName(),
                        "24 hours"
                );
            } catch (Exception e) {
                log.error("Failed to send reminder email to: {}", verification.getUser().getEmail(), e);
            }
        }

        log.info("Sent {} verification reminders", expiringVerifications.size());
    }
}