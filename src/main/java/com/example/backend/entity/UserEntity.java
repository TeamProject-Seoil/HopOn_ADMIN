// src/main/java/com/example/backend/entity/UserEntity.java
package com.example.backend.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(
    name = "users",
    indexes = {
        @Index(name = "ix_users_userid", columnList = "userid", unique = true),
        @Index(name = "ix_users_email",  columnList = "email"),
        @Index(name = "ix_users_role_status", columnList = "role,approval_status")
    }
)
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_num")
    private Long userNum;

    @Column(name = "userid", nullable = false, unique = true, length = 50)
    private String userid;

    @Column(name = "username", length = 100)
    private String username;

    @Column(name = "password", nullable = false, length = 255)
    private String password;

    /**
     * 관리자 생성 API에서 email은 선택값이므로 nullable=true로 완화.
     * DB별 unique(null) 처리:
     *  - MySQL/InnoDB: 여러 NULL 허용
     *  - PostgreSQL: UNIQUE는 NULL을 서로 다른 값으로 취급(여러 NULL 허용)
     * 필요 시 애플리케이션 레벨에서 중복검사만 수행.
     */
    @Column(name = "email", nullable = true, unique = true, length = 100)
    private String email;

    @Column(name = "tel", length = 20)
    private String tel;

    @Lob
    @Column(name = "profile_image", columnDefinition = "LONGBLOB")
    private byte[] profileImage;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Role role;

    @Column(name = "company", length = 100)
    private String company;

    /**
     * 드라이버가 아닐 경우 null 저장이 필요하므로 nullable=true로 완화.
     * 드라이버일 때만 PENDING/APPROVED/REJECTED 사용.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "approval_status", nullable = true, length = 20)
    private ApprovalStatus approvalStatus;

    // DB DEFAULT CURRENT_TIMESTAMP 읽기 전용 매핑 (있다면)
    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @Column(name = "last_refresh_at")
    private LocalDateTime lastRefreshAt;
}
