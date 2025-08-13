package com.HYYPS.HYYPS_Backend.userauth.controller;

import com.HYYPS.HYYPS_Backend.userauth.dto.ApiResponseDto;
import com.HYYPS.HYYPS_Backend.userauth.service.FileUploadService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/upload")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "file-upload-api", description = "Handles File Upload APIs")
@SecurityRequirement(name = "Bearer Authentication")
public class FileUploadController {

    private final FileUploadService fileUploadService;

    @PostMapping("/image")
    @Operation(
            summary = "Upload image file",
            description = "Upload an image file to AWS S3 (JPEG, PNG, GIF, WEBP)"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Image uploaded successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "Image uploaded successfully",
                        "data": {
                            "fileUrl": "https://your-bucket.s3.amazonaws.com/images/uuid-filename.jpg",
                            "fileType": "image"
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "400", description = "Invalid file type or size"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> uploadImage(
            @Parameter(description = "Image file to upload")
            @RequestParam("file") MultipartFile file) {

        String fileUrl = fileUploadService.uploadFile(file, "images");

        Map<String, Object> response = new HashMap<>();
        response.put("fileUrl", fileUrl);
        response.put("fileType", "image");

        return ResponseEntity.ok(ApiResponseDto.success("Image uploaded successfully", response));
    }

    @PostMapping("/video")
    @Operation(
            summary = "Upload video file",
            description = "Upload a video file to AWS S3 (MP4, AVI, MOV, WMV)"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Video uploaded successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "Video uploaded successfully",
                        "data": {
                            "fileUrl": "https://your-bucket.s3.amazonaws.com/videos/uuid-filename.mp4",
                            "fileType": "video"
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "400", description = "Invalid file type or size"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> uploadVideo(
            @Parameter(description = "Video file to upload")
            @RequestParam("file") MultipartFile file) {

        String fileUrl = fileUploadService.uploadFile(file, "videos");

        Map<String, Object> response = new HashMap<>();
        response.put("fileUrl", fileUrl);
        response.put("fileType", "video");

        return ResponseEntity.ok(ApiResponseDto.success("Video uploaded successfully", response));
    }

    @PostMapping("/document")
    @Operation(
            summary = "Upload document file",
            description = "Upload a PDF document to AWS S3"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Document uploaded successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    {
                        "success": true,
                        "message": "Document uploaded successfully",
                        "data": {
                            "fileUrl": "https://your-bucket.s3.amazonaws.com/documents/uuid-filename.pdf",
                            "fileType": "document"
                        },
                        "timestamp": 1703123456789
                    }
                    """)
                    )
            ),
            @ApiResponse(responseCode = "400", description = "Invalid file type or size"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> uploadDocument(
            @Parameter(description = "PDF document to upload")
            @RequestParam("file") MultipartFile file) {

        String fileUrl = fileUploadService.uploadFile(file, "documents");

        Map<String, Object> response = new HashMap<>();
        response.put("fileUrl", fileUrl);
        response.put("fileType", "document");

        return ResponseEntity.ok(ApiResponseDto.success("Document uploaded successfully", response));
    }
}