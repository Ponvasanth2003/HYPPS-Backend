package com.HYYPS.HYYPS_Backend.userauth.repository;

import com.HYYPS.HYYPS_Backend.userauth.entity.KycSubmissionEntity;
import com.HYYPS.HYYPS_Backend.userauth.entity.User;
import com.HYYPS.HYYPS_Backend.userauth.enums.VerificationStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface KycSubmissionRepository extends JpaRepository<KycSubmissionEntity, Long> {

    Optional<KycSubmissionEntity> findByUser(User user);

    List<KycSubmissionEntity> findByKycStatus(VerificationStatus status);

    Page<KycSubmissionEntity> findByKycStatus(VerificationStatus status, Pageable pageable);

    @Query("SELECT COUNT(k) FROM KycSubmissionEntity k WHERE k.kycStatus = :status")
    long countByStatus(VerificationStatus status);
}