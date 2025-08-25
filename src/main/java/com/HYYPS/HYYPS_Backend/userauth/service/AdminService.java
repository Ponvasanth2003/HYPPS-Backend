package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.*;
import com.HYYPS.HYYPS_Backend.userauth.entity.RoleEntity;
import com.HYYPS.HYYPS_Backend.userauth.entity.User;
import com.HYYPS.HYYPS_Backend.userauth.entity.UserRole;
import com.HYYPS.HYYPS_Backend.userauth.repository.RoleRepository;
import com.HYYPS.HYYPS_Backend.userauth.repository.UserRepository;
import com.HYYPS.HYYPS_Backend.userauth.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AdminService {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final RoleRepository roleRepository;
    private final RoleService roleService;
    private final RedisTemplate<String, String> redisTemplate;

    // =============================================================================
    // USER MANAGEMENT
    // =============================================================================

    public ApiResponseDto<Map<String, Object>> getAllUsers(int page, int size, String sortBy, String sortDir, String search) {
        try {
            Pageable pageable = PageRequest.of(page, size,
                    sortDir.equals("desc") ? Sort.by(sortBy).descending() : Sort.by(sortBy).ascending());

            Page<User> userPage;
            if (search != null && !search.trim().isEmpty()) {
                userPage = userRepository.findByNameContainingIgnoreCaseOrEmailContainingIgnoreCase(
                        search.trim(), search.trim(), pageable);
            } else {
                userPage = userRepository.findAll(pageable);
            }

            List<Map<String, Object>> users = userPage.getContent().stream()
                    .map(this::createUserSummaryMap)
                    .collect(Collectors.toList());

            Map<String, Object> response = new HashMap<>();
            response.put("users", users);
            response.put("pagination", createPaginationMap(userPage));

            return ApiResponseDto.success("Users retrieved successfully", response);
        } catch (Exception e) {
            log.error("Failed to retrieve users", e);
            return ApiResponseDto.error("Failed to retrieve users");
        }
    }

    public ApiResponseDto<Map<String, Object>> getUserById(Long userId) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            Map<String, Object> userData = createDetailedUserMap(user);
            return ApiResponseDto.success("User retrieved successfully", userData);
        } catch (Exception e) {
            log.error("Failed to retrieve user with ID: {}", userId, e);
            return ApiResponseDto.error("User not found");
        }
    }

    public ApiResponseDto<Map<String, Object>> updateUser(Long userId, AdminUpdateUserRequestDto request) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Update fields if provided
            if (request.getName() != null && !request.getName().trim().isEmpty()) {
                user.setName(request.getName().trim());
            }

            if (request.getEmail() != null && !request.getEmail().trim().isEmpty()) {
                String newEmail = request.getEmail().trim();
                if (!user.getEmail().equals(newEmail) && userRepository.existsByEmail(newEmail)) {
                    return ApiResponseDto.error("Email already exists");
                }
                user.setEmail(newEmail);
            }

            if (request.getIsActive() != null) {
                user.setIsActive(request.getIsActive());
            }

            if (request.getIsEmailVerified() != null) {
                user.setIsEmailVerified(request.getIsEmailVerified());
            }

            if (request.getPhoneNumber() != null) {
                user.setPhoneNumber(request.getPhoneNumber().trim().isEmpty() ? null : request.getPhoneNumber().trim());
            }

            if (request.getProfilePicture() != null) {
                user.setProfilePicture(request.getProfilePicture().trim().isEmpty() ? null : request.getProfilePicture().trim());
            }

            user = userRepository.save(user);
            Map<String, Object> userData = createDetailedUserMap(user);

            log.info("User {} updated successfully by admin", userId);
            return ApiResponseDto.success("User updated successfully", userData);
        } catch (Exception e) {
            log.error("Failed to update user with ID: {}", userId, e);
            return ApiResponseDto.error("Failed to update user");
        }
    }

    public ApiResponseDto<Void> updateUserStatus(Long userId, UpdateUserStatusRequestDto request) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            user.setIsActive(request.getIsActive());
            userRepository.save(user);

            log.info("User {} status updated to: {}, reason: {}", userId, request.getIsActive(), request.getReason());
            return ApiResponseDto.success(
                    request.getIsActive() ? "User activated successfully" : "User deactivated successfully"
            );
        } catch (Exception e) {
            log.error("Failed to update user status for ID: {}", userId, e);
            return ApiResponseDto.error("Failed to update user status");
        }
    }

    public ApiResponseDto<Void> deleteUser(Long userId) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Delete user role mappings first
            userRoleRepository.deleteByUser(user);

            // Delete user
            userRepository.delete(user);

            log.info("User {} deleted successfully by admin", userId);
            return ApiResponseDto.success("User deleted successfully");
        } catch (Exception e) {
            log.error("Failed to delete user with ID: {}", userId, e);
            return ApiResponseDto.error("Failed to delete user");
        }
    }

    // =============================================================================
    // ROLE MANAGEMENT
    // =============================================================================

    public ApiResponseDto<Map<String, Object>> createRole(CreateRoleRequestDto request) {
        try {
            String roleName = request.getRoleName().toUpperCase().trim();

            // Check if role already exists
            if (roleRepository.existsByRoleName(roleName)) {
                return ApiResponseDto.error("Role already exists");
            }

            RoleEntity role = new RoleEntity();
            role.setRoleName(roleName);
            role.setIsActive(request.getIsActive());
            role = roleRepository.save(role);

            Map<String, Object> response = new HashMap<>();
            response.put("roleId", role.getRoleId());
            response.put("roleName", role.getRoleName());
            response.put("isActive", role.getIsActive());

            log.info("Role {} created successfully", roleName);
            return ApiResponseDto.success("Role created successfully", response);
        } catch (Exception e) {
            log.error("Failed to create role: {}", request.getRoleName(), e);
            return ApiResponseDto.error("Failed to create role");
        }
    }

    public ApiResponseDto<Map<String, Object>> updateRole(Long roleId, UpdateRoleRequestDto request) {
        try {
            RoleEntity role = roleRepository.findById(roleId)
                    .orElseThrow(() -> new RuntimeException("Role not found"));

            if (request.getRoleName() != null && !request.getRoleName().trim().isEmpty()) {
                String newRoleName = request.getRoleName().toUpperCase().trim();
                if (!role.getRoleName().equals(newRoleName) &&
                        roleRepository.existsByRoleName(newRoleName)) {
                    return ApiResponseDto.error("Role name already exists");
                }
                role.setRoleName(newRoleName);
            }

            if (request.getIsActive() != null) {
                role.setIsActive(request.getIsActive());
            }

            role = roleRepository.save(role);

            Map<String, Object> response = new HashMap<>();
            response.put("roleId", role.getRoleId());
            response.put("roleName", role.getRoleName());
            response.put("isActive", role.getIsActive());

            log.info("Role {} updated successfully", roleId);
            return ApiResponseDto.success("Role updated successfully", response);
        } catch (Exception e) {
            log.error("Failed to update role with ID: {}", roleId, e);
            return ApiResponseDto.error("Failed to update role");
        }
    }

    public ApiResponseDto<Void> deleteRole(Long roleId) {
        try {
            RoleEntity role = roleRepository.findById(roleId)
                    .orElseThrow(() -> new RuntimeException("Role not found"));

            // Check if role is assigned to any users
            long userCount = userRoleRepository.countByRole(role);
            if (userCount > 0) {
                return ApiResponseDto.error("Cannot delete role. It is assigned to " + userCount + " users.");
            }

            roleRepository.delete(role);
            log.info("Role {} deleted successfully", roleId);
            return ApiResponseDto.success("Role deleted successfully");
        } catch (Exception e) {
            log.error("Failed to delete role with ID: {}", roleId, e);
            return ApiResponseDto.error("Failed to delete role");
        }
    }

    public ApiResponseDto<Map<String, Object>> assignRoleToUser(Long userId, AssignRoleRequestDto request) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            RoleEntity role = roleService.findByRoleId(request.getRoleId());

            // Check if user already has this role
            if (userRoleRepository.existsByUserAndRole(user, role)) {
                return ApiResponseDto.error("Role already assigned to user");
            }

            // Create user-role mapping
            UserRole userRole = new UserRole();
            userRole.setUser(user);
            userRole.setRole(role);
            userRole.setIsOnboarded(request.getIsOnboarded());
            userRoleRepository.save(userRole);

            Map<String, Object> response = new HashMap<>();
            response.put("userId", userId);
            response.put("roleId", role.getRoleId());
            response.put("roleName", role.getRoleName());
            response.put("isOnboarded", request.getIsOnboarded());

            log.info("Role {} assigned to user {} by admin", role.getRoleName(), userId);
            return ApiResponseDto.success("Role assigned successfully", response);
        } catch (Exception e) {
            log.error("Failed to assign role {} to user {}", request.getRoleId(), userId, e);
            return ApiResponseDto.error("Failed to assign role");
        }
    }

    public ApiResponseDto<Void> removeRoleFromUser(Long userId, Long roleId) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            RoleEntity role = roleService.findByRoleId(roleId);

            UserRole userRole = userRoleRepository.findByUserAndRole(user, role)
                    .orElseThrow(() -> new RuntimeException("Role not assigned to user"));

            userRoleRepository.delete(userRole);

            log.info("Role {} removed from user {} by admin", role.getRoleName(), userId);
            return ApiResponseDto.success("Role removed successfully");
        } catch (Exception e) {
            log.error("Failed to remove role {} from user {}", roleId, userId, e);
            return ApiResponseDto.error("Failed to remove role");
        }
    }

    // =============================================================================
    // ANALYTICS
    // =============================================================================

    public ApiResponseDto<Map<String, Object>> getUserAnalytics() {
        try {
            long totalUsers = userRepository.count();
            long activeUsers = userRepository.countByIsActiveTrue();
            long verifiedUsers = userRepository.countByIsEmailVerifiedTrue();
            long newUsersToday = userRepository.countByCreatedAtAfter(LocalDateTime.now().minusDays(1));
            long newUsersThisWeek = userRepository.countByCreatedAtAfter(LocalDateTime.now().minusDays(7));
            long newUsersThisMonth = userRepository.countByCreatedAtAfter(LocalDateTime.now().minusDays(30));

            // Get role statistics
            List<Object[]> roleStats = userRoleRepository.getRoleStatistics();
            Map<String, Long> usersByRole = new HashMap<>();
            for (Object[] stat : roleStats) {
                usersByRole.put((String) stat[0], (Long) stat[1]);
            }

            double emailVerificationRate = totalUsers > 0 ? (double) verifiedUsers / totalUsers * 100 : 0;
            double averageRolesPerUser = totalUsers > 0 ? (double) userRoleRepository.count() / totalUsers : 0;

            Map<String, Object> analytics = new HashMap<>();
            analytics.put("totalUsers", totalUsers);
            analytics.put("activeUsers", activeUsers);
            analytics.put("verifiedUsers", verifiedUsers);
            analytics.put("newUsersToday", newUsersToday);
            analytics.put("newUsersThisWeek", newUsersThisWeek);
            analytics.put("newUsersThisMonth", newUsersThisMonth);
            analytics.put("usersByRole", usersByRole);
            analytics.put("emailVerificationRate", Math.round(emailVerificationRate * 100.0) / 100.0);
            analytics.put("averageRolesPerUser", Math.round(averageRolesPerUser * 100.0) / 100.0);

            return ApiResponseDto.success("User analytics retrieved successfully", analytics);
        } catch (Exception e) {
            log.error("Failed to retrieve user analytics", e);
            return ApiResponseDto.error("Failed to retrieve analytics");
        }
    }

    public ApiResponseDto<Map<String, Object>> getLoginAnalytics(String period) {
        try {
            // This would require a login_events table to track login statistics
            // For now, returning mock data structure
            Map<String, Object> analytics = new HashMap<>();
            analytics.put("period", period);
            analytics.put("totalLogins", 0);
            analytics.put("uniqueLogins", 0);
            analytics.put("socialLogins", 0);
            analytics.put("failedLogins", 0);
            analytics.put("dailyLogins", List.of());

            // TODO: Implement actual login analytics when login_events table is created

            return ApiResponseDto.success("Login analytics retrieved successfully", analytics);
        } catch (Exception e) {
            log.error("Failed to retrieve login analytics", e);
            return ApiResponseDto.error("Failed to retrieve login analytics");
        }
    }

    // =============================================================================
    // SYSTEM MANAGEMENT
    // =============================================================================

    public ApiResponseDto<Map<String, Object>> getSystemStats() {
        try {
            Map<String, Object> stats = new HashMap<>();
            stats.put("totalUsers", userRepository.count());
            stats.put("totalRoles", roleRepository.count());
            stats.put("totalUserRoleMappings", userRoleRepository.count());
            stats.put("activeUsers", userRepository.countByIsActiveTrue());
            stats.put("verifiedUsers", userRepository.countByIsEmailVerifiedTrue());
            stats.put("timestamp", LocalDateTime.now());

            return ApiResponseDto.success("System statistics retrieved successfully", stats);
        } catch (Exception e) {
            log.error("Failed to retrieve system statistics", e);
            return ApiResponseDto.error("Failed to retrieve system statistics");
        }
    }

    public ApiResponseDto<Void> toggleMaintenanceMode(boolean enabled, String message) {
        try {
            String maintenanceKey = "system:maintenance";

            if (enabled) {
                Map<String, Object> maintenanceInfo = new HashMap<>();
                maintenanceInfo.put("enabled", true);
                maintenanceInfo.put("message", message != null ? message : "System is under maintenance");
                maintenanceInfo.put("enabledAt", LocalDateTime.now().toString());

                // Store indefinitely until disabled
                redisTemplate.opsForValue().set(maintenanceKey, maintenanceInfo.toString());
            } else {
                redisTemplate.delete(maintenanceKey);
            }

            log.info("Maintenance mode {} by admin. Message: {}",
                    enabled ? "enabled" : "disabled", message);

            return ApiResponseDto.success(
                    enabled ? "Maintenance mode enabled" : "Maintenance mode disabled"
            );
        } catch (Exception e) {
            log.error("Failed to toggle maintenance mode", e);
            return ApiResponseDto.error("Failed to toggle maintenance mode");
        }
    }

    public ApiResponseDto<Map<String, Object>> getMaintenanceStatus() {
        try {
            String maintenanceKey = "system:maintenance";
            String maintenanceInfo = redisTemplate.opsForValue().get(maintenanceKey);

            Map<String, Object> status = new HashMap<>();
            if (maintenanceInfo != null) {
                status.put("enabled", true);
                status.put("message", "System is under maintenance");
                // TODO: Parse stored JSON for detailed info
            } else {
                status.put("enabled", false);
                status.put("message", "System is operational");
            }
            status.put("timestamp", LocalDateTime.now());

            return ApiResponseDto.success("Maintenance status retrieved", status);
        } catch (Exception e) {
            log.error("Failed to retrieve maintenance status", e);
            return ApiResponseDto.error("Failed to retrieve maintenance status");
        }
    }

    // =============================================================================
    // HELPER METHODS
    // =============================================================================

    private Map<String, Object> createUserSummaryMap(User user) {
        List<UserRole> userRoles = userRoleRepository.findByUser(user);
        List<String> roleNames = userRoles.stream()
                .map(ur -> ur.getRole().getRoleName())
                .collect(Collectors.toList());

        Map<String, Object> userData = new HashMap<>();
        userData.put("id", user.getId());
        userData.put("name", user.getName());
        userData.put("email", user.getEmail());
        userData.put("isEmailVerified", user.getIsEmailVerified());
        userData.put("isActive", user.getIsActive());
        userData.put("phoneNumber", user.getPhoneNumber());
        userData.put("dateOfBirth", user.getDateOfBirth());
        userData.put("profilePicture", user.getProfilePicture());
        userData.put("createdAt", user.getCreatedAt());
        userData.put("updatedAt", user.getUpdatedAt());
        userData.put("lastLogin", user.getLastLogin());
        userData.put("totalRoles", roleNames.size());
        userData.put("roles", roleNames);

        return userData;
    }

    private Map<String, Object> createDetailedUserMap(User user) {
        List<UserRole> userRoles = userRoleRepository.findByUser(user);
        List<Map<String, Object>> roles = userRoles.stream()
                .map(ur -> {
                    Map<String, Object> roleInfo = new HashMap<>();
                    roleInfo.put("roleId", ur.getRole().getRoleId());
                    roleInfo.put("roleName", ur.getRole().getRoleName());
                    roleInfo.put("isOnboarded", ur.getIsOnboarded());
                    // Add assignedAt if UserRole has createdAt field
                    // roleInfo.put("assignedAt", ur.getCreatedAt());
                    return roleInfo;
                })
                .collect(Collectors.toList());

        Map<String, Object> userData = new HashMap<>();
        userData.put("id", user.getId());
        userData.put("name", user.getName());
        userData.put("email", user.getEmail());
        userData.put("isEmailVerified", user.getIsEmailVerified());
        userData.put("isActive", user.getIsActive());
        userData.put("phoneNumber", user.getPhoneNumber());
        userData.put("dateOfBirth", user.getDateOfBirth());
        userData.put("profilePicture", user.getProfilePicture());
        userData.put("createdAt", user.getCreatedAt());
        userData.put("updatedAt", user.getUpdatedAt());
        userData.put("lastLogin", user.getLastLogin());
        userData.put("totalRoles", roles.size());
        userData.put("roles", roles);

        return userData;
    }

    private Map<String, Object> createPaginationMap(Page<?> page) {
        Map<String, Object> pagination = new HashMap<>();
        pagination.put("page", page.getNumber());
        pagination.put("size", page.getSize());
        pagination.put("totalElements", page.getTotalElements());
        pagination.put("totalPages", page.getTotalPages());
        pagination.put("isFirst", page.isFirst());
        pagination.put("isLast", page.isLast());
        pagination.put("hasNext", page.hasNext());
        pagination.put("hasPrevious", page.hasPrevious());

        return pagination;
    }
}