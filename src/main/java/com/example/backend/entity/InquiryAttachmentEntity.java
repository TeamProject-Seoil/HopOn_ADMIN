// src/main/java/com/example/backend/entity/InquiryAttachmentEntity.java
package com.example.backend.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity @Table(name = "inquiry_attachment")
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class InquiryAttachmentEntity {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name = "inquiry_id", nullable = false)
    private InquiryEntity inquiry;

    @Column(length = 200, nullable = false)
    private String filename;

    @Column(length = 100, nullable = false)
    private String contentType;

    @Lob @Basic(fetch = FetchType.LAZY)
    private byte[] bytes;

    private long size;
}
