package com.HYYPS.HYYPS_Backend.userauth.repository;

import com.HYYPS.HYYPS_Backend.userauth.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<RoleEntity, Long> {

    Optional<RoleEntity> findByRoleName(String roleName);

    boolean existsByRoleName(String roleName);
}