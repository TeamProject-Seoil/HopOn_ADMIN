package com.example.backend.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "inquiry")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InquiryEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 작성자 표시(로그인 X 허용)
    @Column(name = "name", length = 60, nullable = false)
    private String name; // 익명 체크시 "익명"

    @Column(name = "userid", length = 120)
    private String userid; // 로그인 상태면 채움(없어도 됨)

    @Column(name = "title", length = 200, nullable = false)
    private String title;

    // DB는 tinytext 이므로 그대로 매핑. (길이가 길다면 DB를 TEXT 이상으로 변경 권장)
    @Lob
    @Column(name = "content", nullable = false, columnDefinition = "tinytext")
    private String content;

    @Column(name = "email", length = 200, nullable = false)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", length = 20, nullable = false)
    private InquiryStatus status;

    // ✅ 새로 추가된 컬럼들
    @Column(name = "is_secret", nullable = false)
    private boolean isSecret = false;

    @Column(name = "password_hash", length = 100)
    private String passwordHash;

    // DB의 DEFAULT CURRENT_TIMESTAMP / ON UPDATE CURRENT_TIMESTAMP 사용
    @Column(name = "created_at", insertable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", insertable = false, updatable = false)
    private LocalDateTime updatedAt;

    @OneToMany(mappedBy = "inquiry", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderBy("id asc")
    private List<InquiryAttachmentEntity> attachments = new ArrayList<>();

    @OneToMany(mappedBy = "inquiry", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderBy("createdAt asc")
    private List<InquiryReplyEntity> replies = new ArrayList<>();

    @PrePersist
    public void prePersist() {
        // status만 안전하게 기본값 보정(DB 기본값을 신뢰하되 null 방지)
        if (status == null)
            status = InquiryStatus.OPEN;
    }
}
