package com.HYYPS.HYYPS_Backend.userauth.repository;

import com.HYYPS.HYYPS_Backend.userauth.entity.UserRole;
import com.HYYPS.HYYPS_Backend.userauth.entity.User;
import com.HYYPS.HYYPS_Backend.userauth.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, Long> {

    List<UserRole> findByUser(User user);

    Optional<UserRole> findByUserAndRole(User user, RoleEntity role);

    void deleteByUserAndRole(User user, RoleEntity role);

    boolean existsByUserAndRole(User user, RoleEntity role);

    @Query("SELECT ur.role.roleName, COUNT(ur) FROM UserRole ur GROUP BY ur.role.roleName")
    List<Object[]> getRoleStatistics();

    long countByRole(RoleEntity role);

    void deleteByUser(User user);
}