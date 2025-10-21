// src/main/java/com/example/backend/entity/InquiryEntity.java
package com.example.backend.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity @Table(name = "inquiry")
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class InquiryEntity {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 작성자 표시(로그인 X 허용)
    @Column(length = 60, nullable = false)
    private String name;          // 익명 체크시 "익명"

    @Column(length = 120)
    private String userid;        // 로그인 상태면 채움(없어도 됨)

    @Column(length = 200, nullable = false)
    private String title;

    @Lob @Column(nullable = false)
    private String content;

    @Column(length = 200, nullable = false)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(length = 20, nullable = false)
    private InquiryStatus status;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    @OneToMany(mappedBy = "inquiry", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderBy("id asc")
    private List<InquiryAttachmentEntity> attachments = new ArrayList<>();

    @OneToMany(mappedBy = "inquiry", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderBy("createdAt asc")
    private List<InquiryReplyEntity> replies = new ArrayList<>();

    @PrePersist
    public void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) createdAt = now;
        if (updatedAt == null) updatedAt = now;
        if (status == null) status = InquiryStatus.OPEN;
    }

    @PreUpdate
    public void preUpdate() { updatedAt = LocalDateTime.now(); }
}
