// src/main/java/com/example/backend/dto/NoticeRequest.java
package com.example.backend.dto;

import com.example.backend.entity.NoticeTarget;
import com.example.backend.entity.NoticeType;
import jakarta.validation.constraints.*;

public record NoticeRequest(
        @NotBlank @Size(max = 200) String title,
        @NotBlank String content,
        @NotNull NoticeType noticeType,
        @NotNull NoticeTarget targetRole
) {}
