package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "File reupload request")
public class FileReuploadDto {

    @Schema(description = "New file URL", example = "https://s3.amazonaws.com/files/new-video.mp4", required = true)
    @NotBlank(message = "File URL is required")
    private String fileUrl;

    @Schema(description = "Optional comment", example = "Updated with better quality video")
    private String comment;
}