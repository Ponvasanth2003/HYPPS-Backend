package com.HYYPS.HYYPS_Backend.userauth.exception;

public class OtpExpiredException extends RuntimeException {
    public OtpExpiredException(String message) {
        super(message);
    }
}
