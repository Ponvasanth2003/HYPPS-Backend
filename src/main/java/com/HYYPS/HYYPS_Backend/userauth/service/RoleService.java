package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.ApiResponseDto;
import com.HYYPS.HYYPS_Backend.userauth.dto.RoleDto;
import com.HYYPS.HYYPS_Backend.userauth.entity.RoleEntity;
import com.HYYPS.HYYPS_Backend.userauth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class RoleService {

    private final RoleRepository roleRepository;

    /**
     * FIXED: Cache only the data (List<RoleDto>), not the entire ApiResponseDto
     * This prevents serialization issues with ResponseEntity
     */
    @Cacheable(value = "roles", key = "'all-roles'")
    public List<RoleDto> getAllRolesData() {
        try {
            List<RoleEntity> roles = roleRepository.findAll();

            List<RoleDto> roleDtos = roles.stream()
                    .map(role -> new RoleDto(role.getRoleId(), role.getRoleName(), null))
                    .collect(Collectors.toList());

            log.info("Retrieved {} roles from database", roleDtos.size());
            return roleDtos;
        } catch (Exception e) {
            log.error("Failed to retrieve roles from database", e);
            throw new RuntimeException("Failed to retrieve roles", e);
        }
    }

    /**
     * Public method that wraps the cached data in ApiResponseDto
     * This method is NOT cached to avoid serialization issues
     */
    public ApiResponseDto<List<RoleDto>> getAllRoles() {
        try {
            List<RoleDto> roleDtos = getAllRolesData();
            log.info("Returning {} roles (from cache or database)", roleDtos.size());
            return ApiResponseDto.success("Roles retrieved successfully", roleDtos);
        } catch (Exception e) {
            log.error("Failed to retrieve roles", e);
            return ApiResponseDto.error("Failed to retrieve roles");
        }
    }

    public RoleEntity findByRoleName(String roleName) {
        return roleRepository.findByRoleName(roleName)
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleName));
    }

    public RoleEntity findByRoleId(Long roleId) {
        return roleRepository.findById(roleId)
                .orElseThrow(() -> new RuntimeException("Role not found with ID: " + roleId));
    }
}