package com.HYYPS.HYYPS_Backend.userauth.repository;

import com.HYYPS.HYYPS_Backend.userauth.entity.TeacherVerificationEntity;
import com.HYYPS.HYYPS_Backend.userauth.entity.User;
import com.HYYPS.HYYPS_Backend.userauth.enums.VerificationStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface TeacherVerificationRepository extends JpaRepository<TeacherVerificationEntity, Long> {

    Optional<TeacherVerificationEntity> findByUser(User user);

    List<TeacherVerificationEntity> findByProfileVerificationStatus(VerificationStatus status);

    Page<TeacherVerificationEntity> findByProfileVerificationStatus(VerificationStatus status, Pageable pageable);

    @Query("SELECT tv FROM TeacherVerificationEntity tv WHERE tv.timerExpiresAt < :currentTime AND tv.profileVerificationStatus = 'PENDING'")
    List<TeacherVerificationEntity> findExpiredPendingVerifications(@Param("currentTime") LocalDateTime currentTime);

    @Query("SELECT tv FROM TeacherVerificationEntity tv WHERE tv.timerExpiresAt BETWEEN :start AND :end AND tv.profileVerificationStatus = :status")
    List<TeacherVerificationEntity> findByTimerExpiresAtBetweenAndProfileVerificationStatus(
            @Param("start") LocalDateTime start,
            @Param("end") LocalDateTime end,
            @Param("status") VerificationStatus status);

    @Query("SELECT COUNT(tv) FROM TeacherVerificationEntity tv WHERE tv.profileVerificationStatus = :status")
    long countByStatus(@Param("status") VerificationStatus status);

    @Query("SELECT tv FROM TeacherVerificationEntity tv JOIN tv.user u WHERE u.email LIKE %:email% OR u.name LIKE %:name%")
    Page<TeacherVerificationEntity> findByUserEmailContainingOrUserNameContaining(
            @Param("email") String email,
            @Param("name") String name,
            Pageable pageable);
}