package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.util.Map;

@Data
@Schema(description = "Teacher dashboard data")
public class TeacherDashboardDto {

    @Schema(description = "Profile verification step")
    private Map<String, Object> profileVerification;

    @Schema(description = "KYC verification step")
    private Map<String, Object> kycVerification;

    @Schema(description = "Timer information")
    private Map<String, Object> timerInfo;

    @Schema(description = "Can create paid classes")
    private Boolean canCreatePaidClasses;

    @Schema(description = "Next steps")
    private String nextSteps;
}