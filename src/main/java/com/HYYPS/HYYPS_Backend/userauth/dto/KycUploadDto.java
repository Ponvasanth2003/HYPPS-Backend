package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "KYC upload request")
public class KycUploadDto {

    @Schema(description = "Government ID URL", example = "https://s3.amazonaws.com/kyc/govt-id.jpg", required = true)
    @NotBlank(message = "Government ID is required")
    private String govtIdUrl;

    @Schema(description = "Bank proof URL", example = "https://s3.amazonaws.com/kyc/bank-proof.jpg", required = true)
    @NotBlank(message = "Bank proof is required")
    private String bankProofUrl;

    @Schema(description = "Selfie with ID URL (optional)", example = "https://s3.amazonaws.com/kyc/selfie.jpg")
    private String selfieWithIdUrl;
}