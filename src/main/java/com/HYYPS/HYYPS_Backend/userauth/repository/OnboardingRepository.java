package com.HYYPS.HYYPS_Backend.userauth.repository;

import com.HYYPS.HYYPS_Backend.userauth.entity.OnboardingEntity;
import com.HYYPS.HYYPS_Backend.userauth.entity.User;
import com.HYYPS.HYYPS_Backend.userauth.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.List;

@Repository
public interface OnboardingRepository extends JpaRepository<OnboardingEntity, Long> {

    Optional<OnboardingEntity> findByUserAndRole(User user, RoleEntity role);

    List<OnboardingEntity> findByUser(User user);

    boolean existsByUserAndRoleAndIsCompleted(User user, RoleEntity role, Boolean isCompleted);
}