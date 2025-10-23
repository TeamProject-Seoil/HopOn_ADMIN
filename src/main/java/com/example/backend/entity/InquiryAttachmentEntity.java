package com.example.backend.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "inquiry_attachment")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InquiryAttachmentEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "inquiry_id", nullable = false)
    private InquiryEntity inquiry;

    @Column(name = "filename", length = 200, nullable = false)
    private String filename;

    @Column(name = "content_type", length = 100, nullable = false)
    private String contentType;

    @Lob
    @Basic(fetch = FetchType.LAZY)
    @Column(name = "bytes")
    private byte[] bytes;

    @Column(name = "size", nullable = false)
    private long size;

    // DB 컬럼 존재 → 읽기 전용 매핑
    @Column(name = "created_at", insertable = false, updatable = false)
    private LocalDateTime createdAt;
}
