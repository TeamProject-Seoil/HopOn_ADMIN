// src/main/java/com/example/backend/repository/UserSessionRepository.java
package com.example.backend.repository;

import com.example.backend.entity.UserEntity;
import com.example.backend.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Modifying;
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

    // ✅ 활성 여부 판단용
    List<UserSession> findByUserAndRevokedIsFalseAndExpiresAtAfter(UserEntity user, LocalDateTime now);

    // ✅ 상세에서 최신순으로 세션 열람
    List<UserSession> findByUserOrderByUpdatedAtDesc(UserEntity user);

    // ✅ 특정 사용자 소유 세션만 타겟팅
    Optional<UserSession> findByIdAndUser(Long id, UserEntity user);

    // ✅ 필터에서 LazyInitializationException 방지: user를 즉시 페치해서 가져온다 (기존)
    @Query("select s from UserSession s join fetch s.user where s.id = :id")
    Optional<UserSession> findByIdFetchUser(@Param("id") Long id);

    // ✅ 해당 사용자 세션 전부 삭제 (하드 삭제)
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from UserSession s where s.user = :user")
    int deleteByUser(@Param("user") UserEntity user);
}
