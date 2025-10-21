// src/main/java/com/example/backend/dto/NoticeResponse.java
package com.example.backend.dto;

import com.example.backend.entity.NoticeTarget;
import com.example.backend.entity.NoticeType;

import java.time.LocalDateTime;

public record NoticeResponse(
        Long id,
        String title,
        String content,
        NoticeType noticeType,
        NoticeTarget targetRole,
        Long viewCount,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {}
