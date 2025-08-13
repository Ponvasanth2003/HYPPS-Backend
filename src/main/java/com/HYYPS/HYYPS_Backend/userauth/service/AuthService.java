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
     * NEW METHOD: Verify OTP, Create Account, and Auto-Login
     * This replaces the old verifyOtpAndCreateUser method
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

            // Step 3: Create user account
            User user = new User();
            user.setName(signupData.getName());
            user.setEmail(signupData.getEmail());
            user.setPassword(passwordEncoder.encode(signupData.getPassword()));
            user.setIsEmailVerified(true);
            user.setIsActive(true);
            user.setLastLogin(LocalDateTime.now()); // Set first login time
            user.setRoles(new HashSet<>()); // Keep for backward compatibility

            User savedUser = userRepository.save(user);
            log.info("User account created successfully for email: {}", request.getEmail());

            // Step 4: Clean up Redis
            redisTemplate.delete(signupKey);

            // Step 5: Get user roles from UserRole entity (new system)
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

            // Generate JWT token
            String token = tokenProvider.generateToken(authentication, savedUser.getRoles());

            // Step 7: Set JWT cookie
            cookieUtil.setJwtCookie(httpResponse, token);
            log.info("JWT token generated and set in cookie for email: {}", request.getEmail());

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
            loginResponse.put("isNewUser", true); // This is always true for signup
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
     * DEPRECATED: Keep for backward compatibility if needed
     * Use verifyOtpCreateAccountAndLogin instead
     */
    @Deprecated
    @Transactional
    public ApiResponseDto<Void> verifyOtpAndCreateUser(OtpVerificationDto request) {
        // Verify OTP
        otpService.verifyOtp(request.getEmail(), request.getOtp());

        // Create user
        String signupKey = "signup:" + request.getEmail();
        String signupJson = redisTemplate.opsForValue().get(signupKey);

        if (signupJson == null) {
            return ApiResponseDto.error("Signup session expired. Please register again.");
        }

        try {
            SignupRequestDto signupData = objectMapper.readValue(signupJson, SignupRequestDto.class);

            User user = new User();
            user.setName(signupData.getName());
            user.setEmail(signupData.getEmail());
            user.setPassword(passwordEncoder.encode(signupData.getPassword()));
            user.setIsEmailVerified(true);
            user.setIsActive(true);
            user.setRoles(new HashSet<>()); // Keep for backward compatibility

            userRepository.save(user);
            redisTemplate.delete(signupKey);

            log.info("User created and temporary signup data deleted for {}", request.getEmail());
            return ApiResponseDto.success("Account created successfully! Please login.");
        } catch (Exception e) {
            log.error("Failed to deserialize signup data for {}", request.getEmail(), e);
            return ApiResponseDto.error("Internal error. Please try again.");
        }
    }

    /**
     * FIXED: Completely restructured login method to avoid transaction issues
     * 1. Removed @Transactional annotation from main method
     * 2. Authenticate first (no transaction needed)
     * 3. Update user info in separate transaction
     * 4. Generate token and return response
     */
    public ApiResponseDto<Map<String, Object>> login(LoginRequestDto request, HttpServletResponse httpResponse) {
        try {
            // Step 1: Authenticate user (NO TRANSACTION - authentication doesn't need DB writes)
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

            // Step 3: Update user login info and get user details (separate transaction)
            Map<String, Object> loginData;
            try {
                loginData = updateUserLoginInfo(request.getEmail());
            } catch (Exception e) {
                log.error("Failed to update user login info for email: {}", request.getEmail(), e);
                return ApiResponseDto.error("Login failed. Please try again.");
            }

            // Step 4: Generate JWT token (no transaction needed)
            @SuppressWarnings("unchecked")
            User user = (User) loginData.get("user");

            try {
                String token = tokenProvider.generateToken(authentication, user.getRoles());
                // Step 5: Set JWT cookie
                cookieUtil.setJwtCookie(httpResponse, token);
            } catch (Exception e) {
                log.error("Failed to generate JWT token for email: {}", request.getEmail(), e);
                return ApiResponseDto.error("Login failed. Please try again.");
            }

            // Step 6: Return response
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
     * FIXED: Enhanced error handling and transaction management
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

            // Get user roles from UserRole entity (new system)
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
     * FIXED: Enhanced token refresh with better error handling
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

            // Generate new token
            String newToken = tokenProvider.generateToken(authentication, user.getRoles());

            // Set new JWT cookie
            cookieUtil.setJwtCookie(httpResponse, newToken);

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
     * FIXED: Restructured social login to avoid transaction issues
     */
    public ApiResponseDto<Map<String, Object>> socialLogin(SocialLoginRequestDto request, HttpServletResponse httpResponse) {
        try {
            // Step 1: Verify social token and get user info (no transaction needed)
            SocialUserInfo socialUserInfo;
            try {
                socialUserInfo = socialAuthService.verifyAndGetUserInfo(request);
            } catch (Exception e) {
                log.error("Social token verification failed for provider: {}", request.getProvider(), e);
                return ApiResponseDto.error("Social authentication failed");
            }

            // Step 2: Create or get user and update login info (separate transaction)
            Map<String, Object> loginData;
            try {
                loginData = createOrUpdateSocialUser(socialUserInfo);
            } catch (Exception e) {
                log.error("Failed to create/update social user for email: {}", socialUserInfo.getEmail(), e);
                return ApiResponseDto.error("Failed to process social login");
            }

            // Step 3: Generate JWT token and set cookie (no transaction needed)
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

                // Generate JWT token
                String token = tokenProvider.generateToken(authentication, user.getRoles());

                // Set JWT cookie
                cookieUtil.setJwtCookie(httpResponse, token);
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
                // Create new user
                user = new User();
                user.setName(socialUserInfo.getName());
                user.setEmail(socialUserInfo.getEmail());
                user.setPassword(passwordEncoder.encode("SOCIAL_LOGIN_" + System.currentTimeMillis())); // Dummy password
                user.setIsEmailVerified(true); // Social providers verify emails
                user.setIsActive(true);
                user.setRoles(new HashSet<>());
                user = userRepository.save(user);
                isNewUser = true;
                log.info("New user created via social login: {}", socialUserInfo.getEmail());
            }

            // Update last login
            user.setLastLogin(LocalDateTime.now());
            user = userRepository.save(user);

            // Get user roles from UserRole entity (new system)
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

    @Deprecated
    private UserProfileDto convertToUserProfile(User user) {
        UserProfileDto profile = new UserProfileDto();
        profile.setId(user.getId());
        profile.setName(user.getName());
        profile.setEmail(user.getEmail());
        profile.setIsEmailVerified(user.getIsEmailVerified());
        profile.setRoles(user.getRoles());
        profile.setCreatedAt(user.getCreatedAt());
        profile.setLastLogin(user.getLastLogin());
        return profile;
    }
}