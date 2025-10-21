// src/main/java/com/example/backend/entity/NoticeEntity.java
package com.example.backend.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "notice")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
public class NoticeEntity {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 200, nullable = false)
    private String title;

    @Lob
    @Column(nullable = false, columnDefinition = "TEXT")
    private String content;

    @Enumerated(EnumType.STRING)
    @Column(name = "notice_type", length = 30, nullable = false)
    private NoticeType noticeType;

    @Enumerated(EnumType.STRING)
    @Column(name = "target_role", length = 20, nullable = false)
    private NoticeTarget targetRole;

    @Column(name = "view_count", nullable = false)
    private Long viewCount;

    // DB가 자동 관리 (DEFAULT/ON UPDATE)
    @Column(name = "created_at", insertable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", insertable = false, updatable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    public void prePersist() {
        if (viewCount == null) viewCount = 0L;
    }
}
