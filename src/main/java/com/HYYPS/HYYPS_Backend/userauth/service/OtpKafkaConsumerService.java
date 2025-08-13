package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.OtpEventDto;
import com.HYYPS.HYYPS_Backend.userauth.utils.KafkaTopics;
import com.HYYPS.HYYPS_Backend.userauth.security.SecurityEventLogger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.annotation.RetryableTopic;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.retry.annotation.Backoff;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class OtpKafkaConsumerService {

    private final OtpService otpService;
    private final EmailService emailService;
    private final KafkaProducerService kafkaProducerService;
    private final SecurityEventLogger securityEventLogger;

    @KafkaListener(topics = KafkaTopics.OTP_GENERATION_TOPIC, groupId = "otp-processor-group")
    @RetryableTopic(
            attempts = "3",
            backoff = @Backoff(delay = 1000, multiplier = 2.0),
            include = {Exception.class}
    )
    public void processOtpEvent(@Payload OtpEventDto otpEvent,
                                @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
                                @Header(KafkaHeaders.RECEIVED_PARTITION) int partition, // Fixed: RECEIVED_PARTITION instead of RECEIVED_PARTITION_ID
                                @Header(KafkaHeaders.OFFSET) long offset,
                                Acknowledgment acknowledgment) {

        log.info("Processing OTP event: {} for email: {} from topic: {}, partition: {}, offset: {}",
                otpEvent.getEventId(), otpEvent.getEmail(), topic, partition, offset);

        try {
            // Store OTP in Redis
            otpService.storeOtp(otpEvent.getEmail(), otpEvent.getOtp());

            // Send email asynchronously
            sendOtpEmail(otpEvent);

            // Log security event
            securityEventLogger.logSecurityEvent(
                    "OTP_GENERATED_VIA_KAFKA",
                    otpEvent.getEmail(),
                    otpEvent.getClientIp()
            );

            // Publish success result
            kafkaProducerService.publishProcessingResult(
                    otpEvent.getEventId(),
                    otpEvent.getEmail(),
                    true,
                    null,
                    otpEvent.getRetryCount()
            );

            // Manual acknowledgment
            acknowledgment.acknowledge();

            log.info("Successfully processed OTP event: {} for email: {}",
                    otpEvent.getEventId(), otpEvent.getEmail());

        } catch (Exception e) {
            log.error("Failed to process OTP event: {} for email: {}",
                    otpEvent.getEventId(), otpEvent.getEmail(), e);

            // Publish failure result
            kafkaProducerService.publishProcessingResult(
                    otpEvent.getEventId(),
                    otpEvent.getEmail(),
                    false,
                    e.getMessage(),
                    otpEvent.getRetryCount()
            );

            // Don't acknowledge - let retry mechanism handle it
            throw new RuntimeException("OTP processing failed", e);
        }
    }

    @KafkaListener(topics = KafkaTopics.OTP_RETRY_TOPIC, groupId = "otp-retry-processor-group")
    public void processOtpRetryEvent(@Payload OtpEventDto otpEvent, Acknowledgment acknowledgment) {
        log.info("Processing OTP retry event: {} for email: {}, retry count: {}",
                otpEvent.getEventId(), otpEvent.getEmail(), otpEvent.getRetryCount());

        // Implement retry logic with exponential backoff
        if (otpEvent.getRetryCount() <= 3) {
            try {
                // Re-process the event
                processOtpEvent(otpEvent, KafkaTopics.OTP_RETRY_TOPIC, 0, 0, acknowledgment);
            } catch (Exception e) {
                log.error("Retry failed for OTP event: {}", otpEvent.getEventId(), e);
                if (otpEvent.getRetryCount() < 3) {
                    kafkaProducerService.publishOtpRetryEvent(otpEvent);
                }
            }
        } else {
            log.error("Maximum retry attempts exceeded for OTP event: {}", otpEvent.getEventId());
            acknowledgment.acknowledge();
        }
    }

    private void sendOtpEmail(OtpEventDto otpEvent) {
        try {
            switch (otpEvent.getEventType()) {
                case SIGNUP_OTP:
                case EMAIL_VERIFICATION_OTP:
                case RESEND_OTP:
                    emailService.sendOtpEmail(otpEvent.getEmail(), otpEvent.getName(), otpEvent.getOtp());
                    break;
                case PASSWORD_RESET_OTP:
                    emailService.sendPasswordResetEmail(otpEvent.getEmail(), otpEvent.getName(), otpEvent.getOtp());
                    break;
                default:
                    log.warn("Unknown OTP event type: {}", otpEvent.getEventType());
            }
        } catch (Exception e) {
            log.error("Failed to send OTP email for event: {}", otpEvent.getEventId(), e);
            throw e; // Re-throw to trigger retry
        }
    }
}