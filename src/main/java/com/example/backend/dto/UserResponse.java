// src/main/java/com/example/backend/dto/UserResponse.java
package com.example.backend.dto;

import com.example.backend.entity.ApprovalStatus;
import com.example.backend.entity.Role;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.time.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponse {
    private Long userNum;
    private String userid;
    private String username;

    private String email;
    private String tel;

    private Role role; // 원본 enum (필요시 유지)
    @JsonProperty("roleLabel")
    private String roleLabel; // 프론트 표시용 한글 라벨

    private boolean hasProfileImage;

    private String company;
    private ApprovalStatus approvalStatus;
    private boolean hasDriverLicenseFile;

    // 가입일 / 마지막 로그인 시각을 ISO(Z)로 내려주기
    @JsonProperty("createdAt")
    private String createdAtIso;

    @JsonProperty("lastLoginAt")
    private String lastLoginAtIso;

    /** LocalDateTime(KST 가정) -> UTC Z 문자열 */
    public static String toIsoOrNull(LocalDateTime t) {
        if (t == null)
            return null;
        ZoneId KST = ZoneId.of("Asia/Seoul");
        return t.atZone(KST).toInstant().toString(); // e.g. 2025-10-17T03:21:45Z
    }
}
