package com.example.backend.controller;

import com.example.backend.dto.ChangePasswordRequest;
import com.example.backend.dto.UserResponse;
import com.example.backend.entity.UserEntity;
import com.example.backend.repository.UserRepository;
import com.example.backend.repository.UserSessionRepository;
import com.example.backend.security.PasswordPolicy;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * 관리자 콘솔 전용: 최소한의 자기정보 조회 & 비밀번호 변경만 제공
 * - 이메일/전화/회사/프로필 이미지 관련 기능 제거
 * - 계정 삭제, 프로필 이미지 업/다운로드 제거
 */
@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Validated
public class UserController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserSessionRepository sessionRepository;

    // ─────────────────────────────────────────────────────────────────────────
    // 내 정보 조회 (관리자)
    // ─────────────────────────────────────────────────────────────────────────
    @GetMapping("/me")
    public ResponseEntity<UserResponse> me(Authentication authentication) {
        String userid = (String) authentication.getPrincipal();
        UserEntity u = userRepository.findByUserid(userid).orElseThrow();

        // 최근 접속 시각 = lastLoginAt vs lastRefreshAt 중 더 최신
        LocalDateTime last = mostRecent(u.getLastLoginAt(), u.getLastRefreshAt());

        return ResponseEntity.ok(toResponse(u, last));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 비밀번호 변경 (현재 비밀번호 확인 + 정책 검사 + 세션 전체 무효화)
    // ─────────────────────────────────────────────────────────────────────────
    @PostMapping("/me/password")
    public ResponseEntity<?> changePassword(Authentication authentication,
                                            @RequestBody @Valid ChangePasswordRequest req) {
        String userid = (String) authentication.getPrincipal();
        var u = userRepository.findByUserid(userid).orElseThrow();

        if (!passwordEncoder.matches(req.getCurrentPassword(), u.getPassword())) {
            return ResponseEntity.status(400).body(Map.of("ok", false, "reason", "BAD_CURRENT_PASSWORD"));
        }

        String reason = PasswordPolicy.validateAndReason(req.getNewPassword());
        if (reason != null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "ok", false,
                    "reason", "PASSWORD_POLICY_VIOLATION",
                    "message", reason
            ));
        }
        if (passwordEncoder.matches(req.getNewPassword(), u.getPassword())) {
            return ResponseEntity.status(400).body(Map.of("ok", false, "reason", "SAME_AS_OLD"));
        }

        u.setPassword(passwordEncoder.encode(req.getNewPassword()));
        userRepository.save(u);

        // 기존 세션 전체 무효화
        var sessions = sessionRepository.findByUserAndRevokedIsFalse(u);
        for (var s : sessions) s.setRevoked(true);
        if (!sessions.isEmpty()) sessionRepository.saveAll(sessions);

        return ResponseEntity.ok(Map.of("ok", true));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 내부 헬퍼
    // ─────────────────────────────────────────────────────────────────────────
    private static LocalDateTime mostRecent(LocalDateTime a, LocalDateTime b) {
        if (a == null) return b;
        if (b == null) return a;
        return a.isAfter(b) ? a : b;
    }

    /** UserResponse 매핑: 관리자 정책에 맞춰 최소 필드만 */
    private UserResponse toResponse(UserEntity u, LocalDateTime last) {
        return UserResponse.builder()
                .userNum(u.getUserNum())
                .userid(u.getUserid())
                .username(u.getUsername())
                .role(u.getRole())
                .approvalStatus(u.getApprovalStatus())
                .hasDriverLicenseFile(false) // 관리자 콘솔에서는 드라이버 셀프 업로드 없음
                .lastLoginAtIso(UserResponse.toIsoOrNull(last))
                .build();
    }
}
