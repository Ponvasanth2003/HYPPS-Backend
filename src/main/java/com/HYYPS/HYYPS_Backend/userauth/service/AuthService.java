package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.entity.User;
import com.HYYPS.HYYPS_Backend.userauth.entity.UserRole;
import com.HYYPS.HYYPS_Backend.userauth.exception.EmailAlreadyExistsException;
import com.HYYPS.HYYPS_Backend.userauth.repository.UserRepository;
import com.HYYPS.HYYPS_Backend.userauth.repository.UserRoleRepository;
import com.HYYPS.HYYPS_Backend.userauth.security.JwtTokenProvider;
import com.HYYPS.HYYPS_Backend.userauth.security.CookieUtil;
import com.HYYPS.HYYPS_Backend.userauth.dto.OtpEventDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;
    private final OtpService otpService;
    private final EmailService emailService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;
    private final SocialAuthService socialAuthService;
    private final RedisTemplate<String, String> redisTemplate;
    private final CookieUtil cookieUtil;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Transactional
    public ApiResponseDto<Void> initiateSignup(SignupRequestDto request, String clientIp) {
        // Validate passwords match
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            return ApiResponseDto.error("Passwords do not match");
        }

        // Check if email already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("Email already registered");
        }

        try {
            // Store signup data in Redis
            String signupKey = "signup:" + request.getEmail();
            String signupJson = objectMapper.writeValueAsString(request);
            redisTemplate.opsForValue().set(signupKey, signupJson, Duration.ofMinutes(10));

            // Generate and publish OTP event via Kafka
            otpService.generateAndPublishOtpEvent(
                    request.getEmail(),
                    request.getName(),
                    OtpEventDto.OtpEventType.SIGNUP_OTP,
                    clientIp
            );

            log.info("Signup initiated and OTP event published for email: {}", request.getEmail());
            return ApiResponseDto.success("OTP sent to your email. Please verify to complete signup.");
        } catch (Exception e) {
            log.error("Failed to initiate signup for email: {}", request.getEmail(), e);
            return ApiResponseDto.error("Internal error. Please try again.");
        }
    }

    /**
     * FIXED: Verify OTP, Create Account, and Auto-Login with database roles in JWT
     */
    @Transactional
    public ApiResponseDto<Map<String, Object>> verifyOtpCreateAccountAndLogin(OtpVerificationDto request, HttpServletResponse httpResponse) {
        try {
            // Step 1: Verify OTP
            otpService.verifyOtp(request.getEmail(), request.getOtp());
            log.info("OTP verified successfully for email: {}", request.getEmail());

            // Step 2: Retrieve signup data from Redis
            String signupKey = "signup:" + request.getEmail();
            String signupJson = redisTemplate.opsForValue().get(signupKey);

            if (signupJson == null) {
                return ApiResponseDto.error("Signup session expired. Please register again.");
            }

            SignupRequestDto signupData = objectMapper.readValue(signupJson, SignupRequestDto.class);

            // Step 3: Create user account (NO user.setRoles() - removed old field)
            User user = new User();
            user.setName(signupData.getName());
            user.setEmail(signupData.getEmail());
            user.setPassword(passwordEncoder.encode(signupData.getPassword()));
            user.setIsEmailVerified(true);
            user.setIsActive(true);
            user.setLastLogin(LocalDateTime.now());

            User savedUser = userRepository.save(user);
            log.info("User account created successfully for email: {}", request.getEmail());

            // Step 4: Clean up Redis
            redisTemplate.delete(signupKey);

            // Step 5: Get user roles from UserRole entity (database table: user_roles_mapping)
            List<UserRole> userRoles = userRoleRepository.findByUser(savedUser);
            List<RoleDto> roles = userRoles.stream()
                    .map(userRole -> new RoleDto(
                            userRole.getRole().getRoleId(),
                            userRole.getRole().getRoleName(),
                            userRole.getIsOnboarded()
                    ))
                    .collect(Collectors.toList());

            // Step 6: Create authentication and generate JWT token
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    savedUser.getEmail(), null, new HashSet<>()
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Get role names from database and generate token
            Set<String> roleNames = userRoles.stream()
                    .map(ur -> ur.getRole().getRoleName())
                    .collect(Collectors.toSet());

            String token = tokenProvider.generateTokenWithRoleNames(authentication, roleNames);

            // Step 7: Set JWT cookie
            cookieUtil.setJwtCookie(httpResponse, token);
            log.info("JWT token generated and set in cookie for email: {} with roles: {}",
                    request.getEmail(), roleNames);

            // Step 8: Create enhanced user profile data
            Map<String, Object> userData = new HashMap<>();
            userData.put("id", savedUser.getId());
            userData.put("name", savedUser.getName());
            userData.put("email", savedUser.getEmail());
            userData.put("isEmailVerified", savedUser.getIsEmailVerified());
            userData.put("createdAt", savedUser.getCreatedAt());
            userData.put("lastLogin", savedUser.getLastLogin());
            userData.put("totalRoles", roles.size());
            userData.put("roles", roles);

            // Step 9: Prepare response
            Map<String, Object> loginResponse = new HashMap<>();
            loginResponse.put("user", userData);
            loginResponse.put("isNewUser", true);
            loginResponse.put("hasRoles", !roles.isEmpty());
            loginResponse.put("totalRoles", roles.size());
            loginResponse.put("roles", roles);

            log.info("Account created and user automatically logged in successfully: {}", request.getEmail());
            return ApiResponseDto.success("Account created successfully! You are now logged in.", loginResponse);

        } catch (Exception e) {
            log.error("Failed to verify OTP, create account, and login for email: {}", request.getEmail(), e);
            return ApiResponseDto.error("Failed to create account. Please try again.");
        }
    }

    /**
     * FIXED: Login method with database roles in JWT token
     */
    public ApiResponseDto<Map<String, Object>> login(LoginRequestDto request, HttpServletResponse httpResponse) {
        try {
            // Step 1: Authenticate user
            Authentication authentication;
            try {
                authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
                );
            } catch (BadCredentialsException e) {
                log.warn("Authentication failed for email: {}", request.getEmail());
                return ApiResponseDto.error("Invalid email or password");
            } catch (AuthenticationException e) {
                log.warn("Authentication failed for email: {}", request.getEmail());
                return ApiResponseDto.error("Invalid email or password");
            }

            // Step 2: Set authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Step 3: Update user login info and get user details
            Map<String, Object> loginData;
            try {
                loginData = updateUserLoginInfo(request.getEmail());
            } catch (Exception e) {
                log.error("Failed to update user login info for email: {}", request.getEmail(), e);
                return ApiResponseDto.error("Login failed. Please try again.");
            }

            // Step 4: Generate JWT token with database roles
            @SuppressWarnings("unchecked")
            User user = (User) loginData.get("user");

            // Get role names from UserRole entity (database table: user_roles_mapping)
            List<UserRole> userRoles = userRoleRepository.findByUser(user);
            Set<String> roleNames = userRoles.stream()
                    .map(ur -> ur.getRole().getRoleName())
                    .collect(Collectors.toSet());

            try {
                String token = tokenProvider.generateTokenWithRoleNames(authentication, roleNames);
                cookieUtil.setJwtCookie(httpResponse, token);
                log.info("JWT token generated for {} with roles: {}", request.getEmail(), roleNames);
            } catch (Exception e) {
                log.error("Failed to generate JWT token for email: {}", request.getEmail(), e);
                return ApiResponseDto.error("Login failed. Please try again.");
            }

            // Step 5: Return response
            @SuppressWarnings("unchecked")
            Map<String, Object> loginResponse = (Map<String, Object>) loginData.get("response");

            log.info("User logged in successfully: {}", request.getEmail());
            return ApiResponseDto.success("Login successful", loginResponse);

        } catch (Exception e) {
            log.error("Login failed for email: {}", request.getEmail(), e);
            return ApiResponseDto.error("Login failed. Please try again.");
        }
    }

    /**
     * Update user login info with proper transaction management
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Map<String, Object> updateUserLoginInfo(String email) {
        try {
            // Get user details
            User user = userRepository.findActiveUserByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found or inactive"));

            // Update last login
            user.setLastLogin(LocalDateTime.now());
            user = userRepository.save(user);

            // Get user roles from UserRole entity (database table: user_roles_mapping)
            List<UserRole> userRoles = userRoleRepository.findByUser(user);
            List<RoleDto> roles = userRoles.stream()
                    .map(userRole -> new RoleDto(
                            userRole.getRole().getRoleId(),
                            userRole.getRole().getRoleName(),
                            userRole.getIsOnboarded()
                    ))
                    .collect(Collectors.toList());

            // Create enhanced user profile data
            Map<String, Object> userData = new HashMap<>();
            userData.put("id", user.getId());
            userData.put("name", user.getName());
            userData.put("email", user.getEmail());
            userData.put("isEmailVerified", user.getIsEmailVerified());
            userData.put("createdAt", user.getCreatedAt());
            userData.put("lastLogin", user.getLastLogin());
            userData.put("totalRoles", roles.size());
            userData.put("roles", roles);

            // Prepare response
            Map<String, Object> loginResponse = new HashMap<>();
            loginResponse.put("user", userData);
            loginResponse.put("hasRoles", !roles.isEmpty());
            loginResponse.put("totalRoles", roles.size());
            loginResponse.put("roles", roles);

            Map<String, Object> result = new HashMap<>();
            result.put("user", user);
            result.put("response", loginResponse);

            return result;

        } catch (Exception e) {
            log.error("Failed to update user login info for email: {}", email, e);
            throw new RuntimeException("Failed to update user login information", e);
        }
    }

    /**
     * Token refresh with database roles
     */
    public ApiResponseDto<Void> refreshToken(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        try {
            String jwt = cookieUtil.getJwtFromCookie(httpRequest);

            if (jwt == null) {
                return ApiResponseDto.error("No token found");
            }

            if (!tokenProvider.validateToken(jwt)) {
                return ApiResponseDto.error("Invalid or expired token");
            }

            String email = tokenProvider.getEmailFromToken(jwt);
            User user = userRepository.findActiveUserByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Create new authentication
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    email, null, new HashSet<>()
            );

            // Get role names from UserRole entity (database table: user_roles_mapping)
            List<UserRole> userRoles = userRoleRepository.findByUser(user);
            Set<String> roleNames = userRoles.stream()
                    .map(ur -> ur.getRole().getRoleName())
                    .collect(Collectors.toSet());

            // Generate new token with actual roles from database
            String newToken = tokenProvider.generateTokenWithRoleNames(authentication, roleNames);

            // Set new JWT cookie
            cookieUtil.setJwtCookie(httpResponse, newToken);
            log.info("Token refreshed for {} with roles: {}", email, roleNames);

            return ApiResponseDto.success("Token refreshed successfully");
        } catch (Exception e) {
            log.error("Token refresh failed", e);
            return ApiResponseDto.error("Token refresh failed");
        }
    }

    public ApiResponseDto<Void> resendOtp(String email, String clientIp) {
        // Try to fetch name from Redis-stored signup data
        String signupKey = "signup:" + email;
        String signupJson = redisTemplate.opsForValue().get(signupKey);
        String name = "User"; // fallback if Redis is empty

        if (signupJson != null) {
            try {
                SignupRequestDto signupData = objectMapper.readValue(signupJson, SignupRequestDto.class);
                name = signupData.getName();
            } catch (Exception e) {
                log.warn("Failed to parse signup JSON for resendOtp: {}", email, e);
            }
        }

        try {
            // Generate and publish OTP event via Kafka
            otpService.generateAndPublishOtpEvent(
                    email,
                    name,
                    OtpEventDto.OtpEventType.RESEND_OTP,
                    clientIp
            );

            return ApiResponseDto.success("OTP resent successfully");
        } catch (Exception e) {
            log.error("Failed to resend OTP for email: {}", email, e);
            return ApiResponseDto.error("Failed to resend OTP. Please try again.");
        }
    }

    public ApiResponseDto<Void> forgotPassword(ForgotPasswordRequestDto request, String clientIp) {
        // Check if user exists
        User user = userRepository.findByEmail(request.getEmail()).orElse(null);

        if (user == null) {
            // Don't reveal if email exists or not for security
            return ApiResponseDto.success("If the email exists, a password reset OTP has been sent");
        }

        try {
            // Generate and publish password reset OTP event via Kafka
            otpService.generateAndPublishOtpEvent(
                    request.getEmail(),
                    user.getName(),
                    OtpEventDto.OtpEventType.PASSWORD_RESET_OTP,
                    clientIp
            );

            log.info("Password reset OTP event published for: {}", request.getEmail());
            return ApiResponseDto.success("Password reset OTP sent to your email");
        } catch (Exception e) {
            log.error("Failed to send password reset OTP for email: {}", request.getEmail(), e);
            return ApiResponseDto.success("If the email exists, a password reset OTP has been sent");
        }
    }

    @Transactional
    public ApiResponseDto<Void> resetPassword(ResetPasswordRequestDto request) {
        // Validate passwords match
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            return ApiResponseDto.error("Passwords do not match");
        }

        try {
            // Find user
            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Verify OTP
            otpService.verifyOtp(request.getEmail(), request.getOtp());

            // Update password
            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            userRepository.save(user);

            log.info("Password reset successfully for user: {}", request.getEmail());
            return ApiResponseDto.success("Password reset successfully");
        } catch (Exception e) {
            log.error("Failed to reset password for email: {}", request.getEmail(), e);
            return ApiResponseDto.error("Failed to reset password. Please try again.");
        }
    }

    /**
     * Social login with database roles in JWT
     */
    public ApiResponseDto<Map<String, Object>> socialLogin(SocialLoginRequestDto request, HttpServletResponse httpResponse) {
        try {
            // Step 1: Verify social token and get user info
            SocialUserInfo socialUserInfo;
            try {
                socialUserInfo = socialAuthService.verifyAndGetUserInfo(request);
            } catch (Exception e) {
                log.error("Social token verification failed for provider: {}", request.getProvider(), e);
                return ApiResponseDto.error("Social authentication failed");
            }

            // Step 2: Create or get user and update login info
            Map<String, Object> loginData;
            try {
                loginData = createOrUpdateSocialUser(socialUserInfo);
            } catch (Exception e) {
                log.error("Failed to create/update social user for email: {}", socialUserInfo.getEmail(), e);
                return ApiResponseDto.error("Failed to process social login");
            }

            // Step 3: Generate JWT token with database roles and set cookie
            @SuppressWarnings("unchecked")
            User user = (User) loginData.get("user");
            @SuppressWarnings("unchecked")
            Boolean isNewUser = (Boolean) loginData.get("isNewUser");

            try {
                // Create authentication token
                Authentication authentication = new UsernamePasswordAuthenticationToken(
                        user.getEmail(), null, new HashSet<>()
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // Get role names from UserRole entity (database table: user_roles_mapping)
                List<UserRole> userRoles = userRoleRepository.findByUser(user);
                Set<String> roleNames = userRoles.stream()
                        .map(ur -> ur.getRole().getRoleName())
                        .collect(Collectors.toSet());

                // Generate JWT token with actual roles from database
                String token = tokenProvider.generateTokenWithRoleNames(authentication, roleNames);

                // Set JWT cookie
                cookieUtil.setJwtCookie(httpResponse, token);
                log.info("Social login token generated for {} with roles: {}",
                        socialUserInfo.getEmail(), roleNames);
            } catch (Exception e) {
                log.error("Failed to generate JWT token for social login: {}", socialUserInfo.getEmail(), e);
                return ApiResponseDto.error("Failed to complete social login");
            }

            // Step 4: Prepare and return response
            @SuppressWarnings("unchecked")
            Map<String, Object> loginResponse = (Map<String, Object>) loginData.get("response");
            loginResponse.put("isNewUser", isNewUser);

            log.info("Social login successful for: {}", socialUserInfo.getEmail());
            return ApiResponseDto.success("Social login successful", loginResponse);

        } catch (Exception e) {
            log.error("Social login failed for provider: {}", request.getProvider(), e);
            return ApiResponseDto.error("Social authentication failed");
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Map<String, Object> createOrUpdateSocialUser(SocialUserInfo socialUserInfo) {
        try {
            // Check if user exists
            User user = userRepository.findByEmail(socialUserInfo.getEmail()).orElse(null);
            boolean isNewUser = false;

            if (user == null) {
                // Create new user (NO user.setRoles() - removed old field)
                user = new User();
                user.setName(socialUserInfo.getName());
                user.setEmail(socialUserInfo.getEmail());
                user.setPassword(passwordEncoder.encode("SOCIAL_LOGIN_" + System.currentTimeMillis()));
                user.setIsEmailVerified(true);
                user.setIsActive(true);
                user = userRepository.save(user);
                isNewUser = true;
                log.info("New user created via social login: {}", socialUserInfo.getEmail());
            }

            // Update last login
            user.setLastLogin(LocalDateTime.now());
            user = userRepository.save(user);

            // Get user roles from UserRole entity (database table: user_roles_mapping)
            List<UserRole> userRoles = userRoleRepository.findByUser(user);
            List<RoleDto> roles = userRoles.stream()
                    .map(userRole -> new RoleDto(
                            userRole.getRole().getRoleId(),
                            userRole.getRole().getRoleName(),
                            userRole.getIsOnboarded()
                    ))
                    .collect(Collectors.toList());

            // Create enhanced user profile data
            Map<String, Object> userData = new HashMap<>();
            userData.put("id", user.getId());
            userData.put("name", user.getName());
            userData.put("email", user.getEmail());
            userData.put("isEmailVerified", user.getIsEmailVerified());
            userData.put("createdAt", user.getCreatedAt());
            userData.put("lastLogin", user.getLastLogin());
            userData.put("totalRoles", roles.size());
            userData.put("roles", roles);

            // Prepare response
            Map<String, Object> loginResponse = new HashMap<>();
            loginResponse.put("user", userData);
            loginResponse.put("hasRoles", !roles.isEmpty());
            loginResponse.put("totalRoles", roles.size());
            loginResponse.put("roles", roles);

            Map<String, Object> result = new HashMap<>();
            result.put("user", user);
            result.put("isNewUser", isNewUser);
            result.put("response", loginResponse);

            return result;

        } catch (Exception e) {
            log.error("Failed to create/update social user for email: {}", socialUserInfo.getEmail(), e);
            throw new RuntimeException("Failed to process social user", e);
        }
    }

    /**
     * DEPRECATED: Old method kept for backward compatibility
     */
    @Deprecated
    @Transactional
    public ApiResponseDto<Void> verifyOtpAndCreateUser(OtpVerificationDto request) {
        otpService.verifyOtp(request.getEmail(), request.getOtp());

        String signupKey = "signup:" + request.getEmail();
        String signupJson = redisTemplate.opsForValue().get(signupKey);

        if (signupJson == null) {
            return ApiResponseDto.error("Signup session expired. Please register again.");
        }

        try {
            SignupRequestDto signupData = objectMapper.readValue(signupJson, SignupRequestDto.class);

            // Create user (NO user.setRoles() - removed old field)
            User user = new User();
            user.setName(signupData.getName());
            user.setEmail(signupData.getEmail());
            user.setPassword(passwordEncoder.encode(signupData.getPassword()));
            user.setIsEmailVerified(true);
            user.setIsActive(true);

            userRepository.save(user);
            redisTemplate.delete(signupKey);

            log.info("User created and temporary signup data deleted for {}", request.getEmail());
            return ApiResponseDto.success("Account created successfully! Please login.");
        } catch (Exception e) {
            log.error("Failed to deserialize signup data for {}", request.getEmail(), e);
            return ApiResponseDto.error("Internal error. Please try again.");
        }
    }
}