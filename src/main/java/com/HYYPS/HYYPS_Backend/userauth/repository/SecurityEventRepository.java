package com.HYYPS.HYYPS_Backend.userauth.repository;

import com.HYYPS.HYYPS_Backend.userauth.entity.SecurityEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {

    Page<SecurityEvent> findByEventType(String eventType, Pageable pageable);

    Page<SecurityEvent> findByUserEmailContaining(String userEmail, Pageable pageable);

    Page<SecurityEvent> findByEventTypeAndUserEmailContaining(
            String eventType, String userEmail, Pageable pageable);

    List<SecurityEvent> findByEventTypeAndTimestampAfter(String eventType, LocalDateTime since);

    List<SecurityEvent> findByClientIpAndTimestampAfter(String clientIp, LocalDateTime since);

    long countByEventTypeAndTimestampAfter(String eventType, LocalDateTime since);
}