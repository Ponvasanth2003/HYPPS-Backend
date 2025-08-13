package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.ApiResponseDto;
import com.HYYPS.HYYPS_Backend.userauth.dto.UserProfileDto;
import com.HYYPS.HYYPS_Backend.userauth.dto.RoleDto;
import com.HYYPS.HYYPS_Backend.userauth.entity.RoleEntity;
import com.HYYPS.HYYPS_Backend.userauth.entity.UserRole;
import com.HYYPS.HYYPS_Backend.userauth.entity.Role;
import com.HYYPS.HYYPS_Backend.userauth.entity.User;
import com.HYYPS.HYYPS_Backend.userauth.repository.UserRepository;
import com.HYYPS.HYYPS_Backend.userauth.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final RoleService roleService;

    public ApiResponseDto<Map<String, Object>> getCurrentUserProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Get user roles from UserRole entity (new system)
        List<UserRole> userRoles = userRoleRepository.findByUser(user);
        List<RoleDto> roles = userRoles.stream()
                .map(userRole -> new RoleDto(
                        userRole.getRole().getRoleId(),
                        userRole.getRole().getRoleName(),
                        userRole.getIsOnboarded()
                ))
                .collect(Collectors.toList());

        // Create enhanced user profile with role information
        Map<String, Object> profileData = new HashMap<>();
        profileData.put("id", user.getId());
        profileData.put("name", user.getName());
        profileData.put("email", user.getEmail());
        profileData.put("isEmailVerified", user.getIsEmailVerified());
        profileData.put("createdAt", user.getCreatedAt());
        profileData.put("lastLogin", user.getLastLogin());
        profileData.put("totalRoles", roles.size());
        profileData.put("roles", roles);
        profileData.put("hasRoles", !roles.isEmpty());

        return ApiResponseDto.success("Profile retrieved successfully", profileData);
    }

    @Deprecated
    public ApiResponseDto<Map<String, Object>> addRole(Role role) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.getRoles().add(role);
        userRepository.save(user);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Role added successfully");
        response.put("roles", user.getRoles());

        log.info("Role {} added for user: {}", role, email);
        return ApiResponseDto.success("Role added successfully", response);
    }

    public ApiResponseDto<Map<String, Object>> getUserRoleStatus() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Get roles from UserRole entity (new system)
        List<UserRole> userRoles = userRoleRepository.findByUser(user);
        List<RoleDto> roles = userRoles.stream()
                .map(userRole -> new RoleDto(
                        userRole.getRole().getRoleId(),
                        userRole.getRole().getRoleName(),
                        userRole.getIsOnboarded()
                ))
                .collect(Collectors.toList());

        Map<String, Object> roleStatus = new HashMap<>();
        roleStatus.put("hasStudent", roles.stream().anyMatch(r -> "STUDENT".equals(r.getRoleName())));
        roleStatus.put("hasTeacher", roles.stream().anyMatch(r -> "TEACHER".equals(r.getRoleName())));
        roleStatus.put("totalRoles", roles.size());
        roleStatus.put("roles", roles);

        return ApiResponseDto.success("Role status retrieved", roleStatus);
    }

    public ApiResponseDto<Map<String, Object>> assignRole(Long roleId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        RoleEntity role = roleService.findByRoleId(roleId);

        // Check if user already has this role
        if (userRoleRepository.existsByUserAndRole(user, role)) {
            return ApiResponseDto.error("Role already assigned to user");
        }

        // Create user-role mapping
        UserRole userRole = new UserRole();
        userRole.setUser(user);
        userRole.setRole(role);
        userRole.setIsOnboarded(false);
        userRoleRepository.save(userRole);

        Map<String, Object> response = new HashMap<>();
        response.put("roleId", role.getRoleId());
        response.put("roleName", role.getRoleName());
        response.put("isOnboarded", false);

        log.info("Role {} assigned to user: {}", role.getRoleName(), email);
        return ApiResponseDto.success("Role assigned successfully", response);
    }

    public ApiResponseDto<Map<String, Object>> getUserRolesWithOnboarding() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<UserRole> userRoles = userRoleRepository.findByUser(user);
        List<RoleDto> roles = userRoles.stream()
                .map(userRole -> new RoleDto(
                        userRole.getRole().getRoleId(),
                        userRole.getRole().getRoleName(),
                        userRole.getIsOnboarded()
                ))
                .collect(Collectors.toList());

        Map<String, Object> response = new HashMap<>();
        response.put("totalRoles", roles.size());
        response.put("roles", roles);

        return ApiResponseDto.success("Role status retrieved", response);
    }

    public ApiResponseDto<Map<String, Object>> removeRole(Long roleId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        RoleEntity role = roleService.findByRoleId(roleId);
        UserRole userRole = userRoleRepository.findByUserAndRole(user, role)
                .orElseThrow(() -> new RuntimeException("Role not found for user"));

        userRoleRepository.delete(userRole);

        Map<String, Object> response = new HashMap<>();
        response.put("roleId", role.getRoleId());
        response.put("roleName", role.getRoleName());

        log.info("Role {} removed from user: {}", role.getRoleName(), email);
        return ApiResponseDto.success("Role deleted successfully", response);
    }

    public ApiResponseDto<Void> completeOnboarding(Long roleId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        RoleEntity role = roleService.findByRoleId(roleId);
        UserRole userRole = userRoleRepository.findByUserAndRole(user, role)
                .orElseThrow(() -> new RuntimeException("Role not found for user"));

        userRole.setIsOnboarded(true);
        userRoleRepository.save(userRole);

        log.info("Onboarding completed for role {} by user: {}", role.getRoleName(), email);
        return ApiResponseDto.success("Onboarding completed successfully");
    }

    // Helper method to get user roles as RoleDto list
    public List<RoleDto> getUserRoles(User user) {
        List<UserRole> userRoles = userRoleRepository.findByUser(user);
        return userRoles.stream()
                .map(userRole -> new RoleDto(
                        userRole.getRole().getRoleId(),
                        userRole.getRole().getRoleName(),
                        userRole.getIsOnboarded()
                ))
                .collect(Collectors.toList());
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