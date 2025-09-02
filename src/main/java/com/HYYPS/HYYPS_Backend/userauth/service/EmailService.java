package com.HYYPS.HYYPS_Backend.userauth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${app.name:UserAuth App}")
    private String appName;

    public void sendOtpEmail(String toEmail, String name, String otp) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("Verify Your Email - " + appName);

            // Create email content
            Context context = new Context();
            context.setVariable("name", name);
            context.setVariable("otp", otp);
            context.setVariable("appName", appName);

            String htmlContent = createOtpEmailTemplate(name, otp);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("OTP email sent successfully to: {}", toEmail);

        } catch (MessagingException e) {
            log.error("Failed to send OTP email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send OTP email", e);
        }
    }

    public void sendPasswordResetEmail(String toEmail, String name, String otp) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("Password Reset - " + appName);

            String htmlContent = createPasswordResetEmailTemplate(name, otp);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Password reset email sent successfully to: {}", toEmail);

        } catch (MessagingException e) {
            log.error("Failed to send password reset email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send password reset email", e);
        }
    }

    public void sendProfileVerifiedEmail(String toEmail, String name) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("Profile Verified - Upload KYC Documents - " + appName);

            String htmlContent = createProfileVerifiedEmailTemplate(name);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Profile verified email sent successfully to: {}", toEmail);

        } catch (MessagingException e) {
            log.error("Failed to send profile verified email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send profile verified email", e);
        }
    }

    public void sendProfileRejectedEmail(String toEmail, String name, String reason) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("Profile Verification Update Required - " + appName);

            String htmlContent = createProfileRejectedEmailTemplate(name, reason);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Profile rejected email sent successfully to: {}", toEmail);

        } catch (MessagingException e) {
            log.error("Failed to send profile rejected email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send profile rejected email", e);
        }
    }

    public void sendKycVerifiedEmail(String toEmail, String name, boolean canCreatePaidClasses) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("KYC Verified - " + (canCreatePaidClasses ? "Ready to Create Paid Classes!" : "Almost Ready!") + " - " + appName);

            String htmlContent = createKycVerifiedEmailTemplate(name, canCreatePaidClasses);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("KYC verified email sent successfully to: {}", toEmail);

        } catch (MessagingException e) {
            log.error("Failed to send KYC verified email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send KYC verified email", e);
        }
    }

    public void sendKycRejectedEmail(String toEmail, String name, String reason) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("KYC Documents Update Required - " + appName);

            String htmlContent = createKycRejectedEmailTemplate(name, reason);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("KYC rejected email sent successfully to: {}", toEmail);

        } catch (MessagingException e) {
            log.error("Failed to send KYC rejected email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send KYC rejected email", e);
        }
    }

    // Missing methods added for VerificationTimerService
    public void sendVerificationExpiredEmail(String toEmail, String name) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("Verification Timer Expired - Action Required - " + appName);

            String htmlContent = createVerificationExpiredEmailTemplate(name);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Verification expired email sent successfully to: {}", toEmail);

        } catch (MessagingException e) {
            log.error("Failed to send verification expired email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send verification expired email", e);
        }
    }

    public void sendVerificationReminderEmail(String toEmail, String name, String timeRemaining) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("Verification Timer Reminder - " + timeRemaining + " Remaining - " + appName);

            String htmlContent = createVerificationReminderEmailTemplate(name, timeRemaining);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Verification reminder email sent successfully to: {}", toEmail);

        } catch (MessagingException e) {
            log.error("Failed to send verification reminder email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send verification reminder email", e);
        }
    }

    // Email Templates

    private String createPasswordResetEmailTemplate(String name, String otp) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Password Reset</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                        .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .header { text-align: center; margin-bottom: 30px; }
                        .otp-code { font-size: 32px; font-weight: bold; color: #dc3545; text-align: center; padding: 20px; background-color: #f8f9fa; border-radius: 8px; margin: 20px 0; letter-spacing: 5px; }
                        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; color: #856404; }
                        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🔐 Password Reset Request</h1>
                        </div>
                        <p>Hello %s,</p>
                        <p>We received a request to reset your password. Please use the following OTP to reset your password:</p>
                        <div class="otp-code">%s</div>
                        <div class="warning">
                            <strong>Security Notice:</strong>
                            <ul>
                                <li>This OTP will expire in 10 minutes</li>
                                <li>Do not share this code with anyone</li>
                                <li>If you didn't request this reset, please ignore this email</li>
                            </ul>
                        </div>
                        <p>If you continue to have problems, please contact our support team.</p>
                        <div class="footer">
                            <p>Best regards,<br>%s Security Team</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(name, otp, appName);
    }

    private String createOtpEmailTemplate(String name, String otp) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Email Verification</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                        .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .header { text-align: center; margin-bottom: 30px; }
                        .otp-code { font-size: 32px; font-weight: bold; color: #007bff; text-align: center; padding: 20px; background-color: #f8f9fa; border-radius: 8px; margin: 20px 0; letter-spacing: 5px; }
                        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Email Verification</h1>
                        </div>
                        <p>Hello %s,</p>
                        <p>Thank you for signing up! Please use the following OTP to verify your email address:</p>
                        <div class="otp-code">%s</div>
                        <p>This OTP will expire in 10 minutes for security reasons.</p>
                        <p>If you didn't request this verification, please ignore this email.</p>
                        <div class="footer">
                            <p>Best regards,<br>%s Team</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(name, otp, appName);
    }

    private String createProfileVerifiedEmailTemplate(String name) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Profile Verified</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                        .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .header { text-align: center; margin-bottom: 30px; }
                        .success { background-color: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0; color: #155724; }
                        .next-step { background-color: #e7f3ff; border: 1px solid #b3d9ff; padding: 15px; border-radius: 5px; margin: 20px 0; color: #0c5aa6; }
                        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Profile Verification Successful!</h1>
                        </div>
                        <p>Hello %s,</p>
                        <div class="success">
                            <strong>Great news!</strong> Your teaching profile has been successfully verified by our admin team.
                        </div>
                        <div class="next-step">
                            <strong>Next Step: Upload KYC Documents</strong>
                            <p>To complete your teacher verification and unlock paid class creation, please upload your KYC documents:</p>
                            <ul>
                                <li>Government-issued ID (Aadhaar, PAN, Passport, etc.)</li>
                                <li>Bank account proof (Passbook, Statement)</li>
                                <li>Optional: Selfie with ID for enhanced security</li>
                            </ul>
                        </div>
                        <p>Please log in to your teacher dashboard to upload these documents.</p>
                        <div class="footer">
                            <p>Best regards,<br>%s Verification Team</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(name, appName);
    }

    private String createProfileRejectedEmailTemplate(String name, String reason) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Profile Verification Update Required</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                        .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .header { text-align: center; margin-bottom: 30px; }
                        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; color: #856404; }
                        .action-required { background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0; color: #721c24; }
                        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Profile Verification Update Required</h1>
                        </div>
                        <p>Hello %s,</p>
                        <div class="action-required">
                            <strong>Action Required:</strong> Your teaching profile submission needs to be updated.
                        </div>
                        <p><strong>Reason for update request:</strong></p>
                        <div class="warning">%s</div>
                        <p>Please upload a new video that addresses the feedback above. You can upload unlimited times until your profile is verified.</p>
                        <p>Log in to your teacher dashboard to upload a new video.</p>
                        <div class="footer">
                            <p>Best regards,<br>%s Verification Team</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(name, reason, appName);
    }

    private String createKycVerifiedEmailTemplate(String name, boolean canCreatePaidClasses) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>KYC Verification Complete</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                        .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .header { text-align: center; margin-bottom: 30px; }
                        .success { background-color: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0; color: #155724; }
                        .celebration { background-color: #e7f3ff; border: 1px solid #b3d9ff; padding: 20px; border-radius: 5px; margin: 20px 0; color: #0c5aa6; text-align: center; }
                        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>KYC Verification Complete!</h1>
                        </div>
                        <p>Hello %s,</p>
                        <div class="success">
                            <strong>Congratulations!</strong> Your KYC documents have been successfully verified.
                        </div>
                        %s
                        <div class="footer">
                            <p>Best regards,<br>%s Team</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(name,
                canCreatePaidClasses ?
                        "<div class=\"celebration\"><h2>You're All Set!</h2><p>You can now create and host paid classes on our platform!</p></div>" :
                        "<div class=\"celebration\"><h2>Almost Ready!</h2><p>Your verification is complete. You'll be able to create paid classes once your 2-day verification timer expires.</p></div>",
                appName);
    }

    private String createKycRejectedEmailTemplate(String name, String reason) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>KYC Documents Update Required</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                        .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .header { text-align: center; margin-bottom: 30px; }
                        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; color: #856404; }
                        .action-required { background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0; color: #721c24; }
                        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>KYC Documents Update Required</h1>
                        </div>
                        <p>Hello %s,</p>
                        <div class="action-required">
                            <strong>Action Required:</strong> Your KYC documents need to be updated.
                        </div>
                        <p><strong>Reason for update request:</strong></p>
                        <div class="warning">%s</div>
                        <p>Please upload new KYC documents that address the feedback above.</p>
                        <p>Required documents:</p>
                        <ul>
                            <li>Clear government-issued ID</li>
                            <li>Valid bank account proof</li>
                            <li>Optional: Selfie with ID</li>
                        </ul>
                        <div class="footer">
                            <p>Best regards,<br>%s Verification Team</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(name, reason, appName);
    }

    // New email templates for timer-related emails
    private String createVerificationExpiredEmailTemplate(String name) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Verification Timer Expired</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                        .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .header { text-align: center; margin-bottom: 30px; }
                        .expired { background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0; color: #721c24; }
                        .action { background-color: #e7f3ff; border: 1px solid #b3d9ff; padding: 15px; border-radius: 5px; margin: 20px 0; color: #0c5aa6; }
                        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Verification Timer Has Expired</h1>
                        </div>
                        <p>Hello %s,</p>
                        <div class="expired">
                            <strong>Timer Expired:</strong> Your teacher verification submission has exceeded the 2-day review period and has been automatically marked for resubmission.
                        </div>
                        <div class="action">
                            <strong>Next Steps:</strong>
                            <p>Don't worry! You can still complete your verification:</p>
                            <ul>
                                <li>Log in to your teacher dashboard</li>
                                <li>Upload a new verification video</li>
                                <li>Our team will review it promptly</li>
                            </ul>
                        </div>
                        <p>We apologize for any delay in reviewing your initial submission. Our team is working hard to process all verifications quickly.</p>
                        <div class="footer">
                            <p>Best regards,<br>%s Verification Team</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(name, appName);
    }

    private String createVerificationReminderEmailTemplate(String name, String timeRemaining) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Verification Reminder</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                        .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .header { text-align: center; margin-bottom: 30px; }
                        .reminder { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; color: #856404; }
                        .info { background-color: #e7f3ff; border: 1px solid #b3d9ff; padding: 15px; border-radius: 5px; margin: 20px 0; color: #0c5aa6; }
                        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Verification Review In Progress</h1>
                        </div>
                        <p>Hello %s,</p>
                        <div class="reminder">
                            <strong>Reminder:</strong> Your teacher verification is currently under review with %s remaining before the automatic expiration.
                        </div>
                        <div class="info">
                            <strong>Current Status:</strong>
                            <p>Our admin team is actively reviewing your submission. No action is needed from your end at this time.</p>
                            <p>If the review period expires, don't worry - you'll be able to resubmit your verification materials.</p>
                        </div>
                        <p>Thank you for your patience as we ensure all teacher verifications meet our quality standards.</p>
                        <div class="footer">
                            <p>Best regards,<br>%s Verification Team</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(name, timeRemaining, appName);
    }
}