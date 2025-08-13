package com.HYYPS.HYYPS_Backend.userauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Standard API response wrapper")
public class ApiResponseDto<T> {

    @Schema(description = "Indicates if the request was successful", example = "true")
    private boolean success;

    @Schema(description = "Response message", example = "Operation completed successfully")
    private String message;

    @Schema(description = "Response data (can be null)")
    private T data;

    @Schema(description = "Response timestamp", example = "1703123456789")
    private long timestamp;

    public static <T> ApiResponseDto<T> success(String message, T data) {
        return new ApiResponseDto<>(true, message, data, System.currentTimeMillis());
    }

    public static <T> ApiResponseDto<T> success(String message) {
        return new ApiResponseDto<>(true, message, null, System.currentTimeMillis());
    }

    public static <T> ApiResponseDto<T> error(String message) {
        return new ApiResponseDto<>(false, message, null, System.currentTimeMillis());
    }
    public boolean isSuccess() {
        return success;
    }
}