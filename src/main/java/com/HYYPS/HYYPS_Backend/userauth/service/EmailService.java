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
}
