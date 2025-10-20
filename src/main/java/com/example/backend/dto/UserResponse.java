package com.example.backend.dto;

import com.example.backend.entity.ApprovalStatus;
import com.example.backend.entity.Role;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.time.*;

@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
public class UserResponse {
    private Long userNum;
    private String userid;
    private String username;
    private String email;
    private String tel;
    private Role role;                        // 기존 코드 그대로 유지
    private boolean hasProfileImage;

    private String company;
    private ApprovalStatus approvalStatus;
    private boolean hasDriverLicenseFile;

    // ⭐ 클라가 받는 필드 이름을 lastLoginAt 으로 직렬화
    @JsonProperty("lastLoginAt")
    private String lastLoginAtIso;            // ISO8601 "…Z"

    /**
     * LocalDateTime(서버 로컬시간, KST 가정) → Instant(UTC, Z) 문자열
     * - DB에 KST 로 저장된 '로컬시각'을 KST 로 해석
     * - 그 순간을 UTC 로 변환해 Z 표기 ISO 로 직렬화
     */
    public static String toIsoOrNull(LocalDateTime t) {
        if (t == null) return null;
        ZoneId KST = ZoneId.of("Asia/Seoul");
        return t.atZone(KST).toInstant().toString(); // 예: 2025-10-17T03:21:45Z
    }
}
