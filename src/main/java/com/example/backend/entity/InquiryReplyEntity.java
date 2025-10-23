package com.example.backend.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "inquiry_reply")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InquiryReplyEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "inquiry_id", nullable = false)
    private InquiryEntity inquiry;

    @Column(name = "message", length = 5000, nullable = false)
    private String message;

    @Column(name = "admin_user_num")
    private Long adminUserNum; // 답변한 관리자 식별(옵션)

    // DB의 DEFAULT CURRENT_TIMESTAMP 사용 → 읽기 전용
    @Column(name = "created_at", insertable = false, updatable = false)
    private LocalDateTime createdAt;
}
