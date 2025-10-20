// src/main/java/com/example/backend/entity/UserSession.java
package com.example.backend.entity;

import java.time.LocalDateTime;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name="user_sessions",
       uniqueConstraints = @UniqueConstraint(columnNames = {"user_num","client_type"}))
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class UserSession {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name="user_num", nullable=false)
    private UserEntity user;

    @Column(name="client_type", nullable=false, length=20)
    private String clientType; // USER_APP | DRIVER_APP | ADMIN_APP

    @Column(name="device_id", nullable=false, length=100)
    private String deviceId;

    @Column(name="refresh_token_hash", nullable=false, length=64)
    private String refreshTokenHash;

    @Column(name="expires_at", nullable=false)
    private LocalDateTime expiresAt;

    @Column(name="revoked", nullable=false)
    private boolean revoked;

    @Column(name="created_at", nullable=false)
    private LocalDateTime createdAt;

    @Column(name="updated_at", nullable=false)
    private LocalDateTime updatedAt;

    @PrePersist
    void onCreate() { createdAt = LocalDateTime.now(); updatedAt = createdAt; }
    @PreUpdate
    void onUpdate() { updatedAt = LocalDateTime.now(); }
}
