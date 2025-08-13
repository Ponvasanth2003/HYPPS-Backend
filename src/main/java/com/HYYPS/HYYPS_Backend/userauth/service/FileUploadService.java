package com.HYYPS.HYYPS_Backend.userauth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.IOException;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class FileUploadService {

    private final S3Client s3Client;

    @Value("${aws.s3.bucket-name}")
    private String bucketName;

    @Value("${aws.s3.base-url}")
    private String baseUrl;

    public String uploadFile(MultipartFile file, String folder) {
        if (file.isEmpty()) {
            throw new RuntimeException("File is empty");
        }

        try {
            // Validate file type
            validateFileType(file);

            // Generate unique filename
            String originalFilename = file.getOriginalFilename();
            String extension = originalFilename.substring(originalFilename.lastIndexOf("."));
            String fileName = folder + "/" + UUID.randomUUID().toString() + extension;

            // Upload to S3
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(fileName)
                    .contentType(file.getContentType())
                    .contentLength(file.getSize())
                    .build();

            s3Client.putObject(putObjectRequest, RequestBody.fromInputStream(file.getInputStream(), file.getSize()));

            String fileUrl = baseUrl + "/" + fileName;
            log.info("File uploaded successfully: {}", fileUrl);

            return fileUrl;

        } catch (IOException e) {
            log.error("Error uploading file to S3", e);
            throw new RuntimeException("Failed to upload file", e);
        }
    }

    public void deleteFile(String fileUrl) {
        try {
            // Extract key from URL
            String key = fileUrl.replace(baseUrl + "/", "");

            DeleteObjectRequest deleteObjectRequest = DeleteObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .build();

            s3Client.deleteObject(deleteObjectRequest);
            log.info("File deleted successfully: {}", fileUrl);

        } catch (Exception e) {
            log.error("Error deleting file from S3: {}", fileUrl, e);
            throw new RuntimeException("Failed to delete file", e);
        }
    }

    private void validateFileType(MultipartFile file) {
        String contentType = file.getContentType();
        String originalFilename = file.getOriginalFilename();

        if (contentType == null || originalFilename == null) {
            throw new RuntimeException("Invalid file");
        }

        // Allowed file types
        if (!isImageFile(contentType) && !isVideoFile(contentType) && !isPdfFile(contentType)) {
            throw new RuntimeException("File type not allowed. Only images, videos, and PDFs are supported.");
        }

        // File size validation (50MB max)
        if (file.getSize() > 50 * 1024 * 1024) {
            throw new RuntimeException("File size exceeds maximum limit of 50MB");
        }
    }

    private boolean isImageFile(String contentType) {
        return contentType.startsWith("image/") &&
                (contentType.equals("image/jpeg") ||
                        contentType.equals("image/png") ||
                        contentType.equals("image/gif") ||
                        contentType.equals("image/webp"));
    }

    private boolean isVideoFile(String contentType) {
        return contentType.startsWith("video/") &&
                (contentType.equals("video/mp4") ||
                        contentType.equals("video/avi") ||
                        contentType.equals("video/mov") ||
                        contentType.equals("video/wmv"));
    }

    private boolean isPdfFile(String contentType) {
        return contentType.equals("application/pdf");
    }
}