package com.HYYPS.HYYPS_Backend.userauth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FileUploadConfig {

    @Value("${app.file-upload.max-size:10MB}")
    private String maxFileSize;

    @Value("${app.file-upload.allowed-types:image/jpeg,image/png,image/jpg,application/pdf,video/mp4,video/avi}")
    private String allowedFileTypes;

    @Value("${app.file-upload.s3-bucket:teacher-verification-files}")
    private String s3Bucket;

    public String getMaxFileSize() {
        return maxFileSize;
    }

    public String[] getAllowedFileTypes() {
        return allowedFileTypes.split(",");
    }

    public String getS3Bucket() {
        return s3Bucket;
    }
}