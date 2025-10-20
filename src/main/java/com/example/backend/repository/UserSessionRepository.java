package com.example.backend.repository;

import com.example.backend.entity.UserEntity;
import com.example.backend.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    Optional<UserSession> findByUserAndClientType(UserEntity user, String clientType);
    Optional<UserSession> findByUserAndClientTypeAndDeviceId(UserEntity user, String clientType, String deviceId);
    Optional<UserSession> findByUserAndClientTypeAndDeviceIdAndRevokedIsFalseAndExpiresAtAfter(
            UserEntity user, String clientType, String deviceId, LocalDateTime now);
    List<UserSession> findByUserAndRevokedIsFalse(UserEntity user);
}
