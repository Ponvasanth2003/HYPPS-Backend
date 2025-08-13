package com.HYYPS.HYYPS_Backend.userauth.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "OTP generation event")
public class OtpEventDto {

    @Schema(description = "Unique event ID")
    private String eventId;

    @Schema(description = "Event type", example = "SIGNUP_OTP")
    private OtpEventType eventType;

    @Schema(description = "User's email address")
    private String email;

    @Schema(description = "User's name")
    private String name;

    @Schema(description = "Generated OTP code")
    private String otp;

    @Schema(description = "Event timestamp")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime timestamp;

    @Schema(description = "Client IP address")
    private String clientIp;

    @Schema(description = "Additional metadata")
    private String metadata;

    @Schema(description = "Retry attempt count")
    private int retryCount;

    public enum OtpEventType {
        SIGNUP_OTP,
        PASSWORD_RESET_OTP,
        RESEND_OTP,
        EMAIL_VERIFICATION_OTP
    }
}