// src/main/java/com/example/backend/entity/InquiryReplyEntity.java
package com.example.backend.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity @Table(name = "inquiry_reply")
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class InquiryReplyEntity {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name = "inquiry_id", nullable = false)
    private InquiryEntity inquiry;

    @Column(length = 5000, nullable = false)
    private String message;

    private Long adminUserNum; // 답변한 관리자 식별(옵션)

    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }
}
