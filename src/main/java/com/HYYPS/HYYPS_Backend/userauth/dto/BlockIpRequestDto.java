package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import lombok.Data;

@Data
@Schema(description = "Block IP request")
public class BlockIpRequestDto {

    @Schema(description = "IP address to block", example = "192.168.1.100", required = true)
    @NotBlank(message = "IP address is required")
    @Pattern(regexp = "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$", message = "Invalid IP address format")
    private String ipAddress;

    @Schema(description = "Reason for blocking", example = "Multiple failed login attempts", required = true)
    @NotBlank(message = "Reason is required")
    private String reason;

    @Schema(description = "Block duration in hours", example = "24")
    @Min(value = 1, message = "Duration must be at least 1 hour")
    @Max(value = 8760, message = "Duration cannot exceed 1 year")
    private Integer durationHours = 24;
}