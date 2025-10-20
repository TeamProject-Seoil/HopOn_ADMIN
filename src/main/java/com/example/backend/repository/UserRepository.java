// src/main/java/com/example/backend/repository/UserRepository.java
package com.example.backend.repository;

import com.example.backend.entity.ApprovalStatus;
import com.example.backend.entity.Role;
import com.example.backend.entity.UserEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    // 기본 조회/중복
    boolean existsByUserid(String userid);
    boolean existsByUseridIgnoreCase(String userid);

    Optional<UserEntity> findByUserid(String userid);
    Optional<UserEntity> findByUseridIgnoreCase(String userid);

    // 드라이버 상태별 조회
    List<UserEntity> findByRoleAndApprovalStatus(Role role, ApprovalStatus approvalStatus);
    Page<UserEntity> findByRoleAndApprovalStatus(Role role, ApprovalStatus approvalStatus, Pageable pageable);

    // 하드 삭제
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from UserEntity u where u.userNum = :num")
    int hardDeleteByUserNum(@Param("num") Long num);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from UserEntity u where lower(u.userid) = lower(:userid)")
    int hardDeleteByUserid(@Param("userid") String userid);
}
