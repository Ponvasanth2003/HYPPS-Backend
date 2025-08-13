package com.HYYPS.HYYPS_Backend.userauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OtpProcessingResultDto {
    private String eventId;
    private String email;
    private boolean success;
    private String errorMessage;
    private int retryCount;
    private LocalDateTime processedAt;
    private String processingNode;

    public static OtpProcessingResultDto success(String eventId, String email, int retryCount) {
        return OtpProcessingResultDto.builder()
                .eventId(eventId)
                .email(email)
                .success(true)
                .retryCount(retryCount)
                .processedAt(LocalDateTime.now())
                .build();
    }

    public static OtpProcessingResultDto failure(String eventId, String email, String errorMessage, int retryCount) {
        return OtpProcessingResultDto.builder()
                .eventId(eventId)
                .email(email)
                .success(false)
                .errorMessage(errorMessage)
                .retryCount(retryCount)
                .processedAt(LocalDateTime.now())
                .build();
    }
}