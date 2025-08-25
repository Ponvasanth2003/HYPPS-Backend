package com.HYYPS.HYYPS_Backend.userauth.repository;

import com.HYYPS.HYYPS_Backend.userauth.entity.User;
import com.HYYPS.HYYPS_Backend.userauth.entity.UserEmailHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserEmailHistoryRepository extends JpaRepository<UserEmailHistory, Long> {

    List<UserEmailHistory> findByUserOrderByCreatedAtDesc(User user);

    Optional<UserEmailHistory> findByUserAndEmail(User user, String email);

    @Query("SELECT CASE WHEN COUNT(h) > 0 THEN true ELSE false END " +
            "FROM UserEmailHistory h WHERE h.email = ?1 AND h.user.id != ?2")
    boolean isEmailUsedByOtherUser(String email, Long currentUserId);

    @Query("SELECT CASE WHEN COUNT(h) > 0 THEN true ELSE false END " +
            "FROM UserEmailHistory h WHERE h.email = ?1 AND h.user = ?2")
    boolean hasUserUsedEmailBefore(String email, User user);

    @Query("SELECT h FROM UserEmailHistory h WHERE h.user = ?1 AND h.isCurrent = true")
    Optional<UserEmailHistory> findCurrentEmailHistory(User user);
}