package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.OtpEventDto;
import com.HYYPS.HYYPS_Backend.userauth.utils.KafkaTopics;
import com.HYYPS.HYYPS_Backend.userauth.dto.OtpProcessingResultDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

@Service
@RequiredArgsConstructor
@Slf4j
public class KafkaProducerService {

    private final KafkaTemplate<String, Object> kafkaTemplate;

    public CompletableFuture<SendResult<String, Object>> publishOtpEvent(OtpEventDto otpEvent) {
        try {
            // Set event ID and timestamp if not already set
            if (otpEvent.getEventId() == null) {
                otpEvent.setEventId(UUID.randomUUID().toString());
            }
            if (otpEvent.getTimestamp() == null) {
                otpEvent.setTimestamp(LocalDateTime.now());
            }

            log.info("Publishing OTP event: {} for email: {}",
                    otpEvent.getEventType(), otpEvent.getEmail());

            CompletableFuture<SendResult<String, Object>> future =
                    kafkaTemplate.send(KafkaTopics.OTP_GENERATION_TOPIC, otpEvent.getEmail(), otpEvent);

            future.whenComplete((result, throwable) -> {
                if (throwable != null) {
                    log.error("Failed to publish OTP event for email: {}",
                            otpEvent.getEmail(), throwable);
                } else {
                    log.info("Successfully published OTP event: {} for email: {} with offset: {}",
                            otpEvent.getEventId(), otpEvent.getEmail(),
                            result.getRecordMetadata().offset());
                }
            });

            return future;
        } catch (Exception e) {
            log.error("Error publishing OTP event for email: {}", otpEvent.getEmail(), e);
            throw new RuntimeException("Failed to publish OTP event", e);
        }
    }

    public void publishOtpRetryEvent(OtpEventDto otpEvent) {
        try {
            otpEvent.setRetryCount(otpEvent.getRetryCount() + 1);
            otpEvent.setTimestamp(LocalDateTime.now());

            log.info("Publishing OTP retry event: {} for email: {}, retry count: {}",
                    otpEvent.getEventId(), otpEvent.getEmail(), otpEvent.getRetryCount());

            kafkaTemplate.send(KafkaTopics.OTP_RETRY_TOPIC, otpEvent.getEmail(), otpEvent);
        } catch (Exception e) {
            log.error("Error publishing OTP retry event for email: {}", otpEvent.getEmail(), e);
        }
    }

    public void publishProcessingResult(String eventId, String email, boolean success,
                                        String errorMessage, int retryCount) {
        try {
            OtpProcessingResultDto result = OtpProcessingResultDto.builder()
                    .eventId(eventId)
                    .email(email)
                    .success(success)
                    .errorMessage(errorMessage)
                    .processedAt(LocalDateTime.now())
                    .retryCount(retryCount)
                    .build();

            kafkaTemplate.send(KafkaTopics.OTP_PROCESSING_RESULT_TOPIC, email, result);
            log.debug("Published processing result for event: {}, success: {}", eventId, success);
        } catch (Exception e) {
            log.error("Error publishing processing result for event: {}", eventId, e);
        }
    }
}