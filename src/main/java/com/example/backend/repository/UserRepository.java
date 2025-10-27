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

    // 상태별 조회(그대로 유지)
    List<UserEntity> findByRoleAndApprovalStatus(Role role, ApprovalStatus approvalStatus);
    Page<UserEntity> findByRoleAndApprovalStatus(Role role, ApprovalStatus approvalStatus, Pageable pageable);

    // ✅ 탭 카운트용 (counts API에서 사용)
    long countByRoleAndApprovalStatus(Role role, ApprovalStatus approvalStatus);

    // ✅ 역할별 인원수 (마지막 관리자 보호용)
    long countByRole(Role role);

    // ✅ 검색 포함 페이지 조회 (userid/username LIKE, q가 null이면 전체)
    @Query("""
           select u
           from UserEntity u
           where u.role = :role
             and u.approvalStatus = :status
             and ( :q is null
                   or lower(u.userid) like lower(concat('%', :q, '%'))
                   or lower(u.username) like lower(concat('%', :q, '%')) )
           """)
    Page<UserEntity> searchByRoleAndStatus(
            @Param("role") Role role,
            @Param("status") ApprovalStatus status,
            @Param("q") String q,
            Pageable pageable
    );

    // 하드 삭제
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from UserEntity u where u.userNum = :num")
    int hardDeleteByUserNum(@Param("num") Long num);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from UserEntity u where lower(u.userid) = lower(:userid)")
    int hardDeleteByUserid(@Param("userid") String userid);
}
