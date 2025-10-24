// src/main/java/com/example/backend/repository/UserSessionRepository.java
package com.example.backend.repository;

import com.example.backend.entity.UserEntity;
import com.example.backend.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    Optional<UserSession> findByUserAndClientType(UserEntity user, String clientType);

    Optional<UserSession> findByUserAndClientTypeAndDeviceId(UserEntity user, String clientType, String deviceId);

    Optional<UserSession> findByUserAndClientTypeAndDeviceIdAndRevokedIsFalseAndExpiresAtAfter(
            UserEntity user, String clientType, String deviceId, LocalDateTime now);

    List<UserSession> findByUserAndRevokedIsFalse(UserEntity user);

    // ✅ 필터에서 LazyInitializationException 방지: user를 즉시 페치해서 가져온다
    @Query("select s from UserSession s join fetch s.user where s.id = :id")
    Optional<UserSession> findByIdFetchUser(@Param("id") Long id);
}
