package com.HYYPS.HYYPS_Backend.userauth.utils;

public class KafkaTopics {
    public static final String OTP_GENERATION_TOPIC = "otp.generation.events";
    public static final String OTP_PROCESSING_RESULT_TOPIC = "otp.processing.results";
    public static final String OTP_RETRY_TOPIC = "otp.retry.events";
    public static final String EMAIL_NOTIFICATION_TOPIC = "email.notification.events";

    // Dead Letter Topics
    public static final String OTP_DLT_TOPIC = "otp.generation.events.dlt";
    public static final String EMAIL_DLT_TOPIC = "email.notification.events.dlt";
}