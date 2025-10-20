// src/main/java/com/example/backend/controller/AuthController.java
package com.example.backend.controller;

import com.example.backend.dto.AuthRequest;
import com.example.backend.dto.AuthResponse;
import com.example.backend.dto.LogoutRequest;
import com.example.backend.entity.ApprovalStatus;
import com.example.backend.entity.Role;
import com.example.backend.entity.UserEntity;
import com.example.backend.entity.UserSession;
import com.example.backend.repository.UserRepository;
import com.example.backend.repository.UserSessionRepository;
import com.example.backend.security.JwtTokenProvider;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Validated
public class AuthController {

    // ── Dependencies ───────────────────────────────────────────────────────────
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final UserSessionRepository sessionRepository;

    // ── Token settings ─────────────────────────────────────────────────────────
    @Value("${jwt.refresh-exp-days}")
    private long refreshExpDays;

    /** 옵션: 절대 수명(일). 설정이 0 이하이면 미적용 */
    @Value("${jwt.refresh-absolute-max-days:0}")
    private long refreshAbsoluteMaxDays;

    // ── Admin-only: LOGIN ─────────────────────────────────────────────────────
    @PostMapping("/login")
    public ResponseEntity<?> login(@Validated @RequestBody AuthRequest req) {
        try {
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getUserid(), req.getPassword())
            );
        } catch (Exception e) {
            log.warn("로그인 실패 - 자격증명 불일치: userid={}", req.getUserid());
            return ResponseEntity.status(401).header("X-Reason", "BAD_CREDENTIALS").build();
        }

        var user = userRepository.findByUserid(req.getUserid())
                .orElseThrow(() -> new BadCredentialsException("User not found"));

        final String role = user.getRole().name();
        final String clientType = req.getClientType();
        final String deviceId   = req.getDeviceId();

        // 관리자 전용 백엔드: ADMIN_APP + ROLE_ADMIN 만 허용
        if (!isAllowed(clientType, role)) {
            log.warn("로그인 실패 - 관리 콘솔 권한 불일치: userid={}, role={}, clientType={}",
                    req.getUserid(), role, clientType);
            return ResponseEntity.status(403).header("X-Reason", "ROLE_NOT_ALLOWED_FOR_APP").build();
        }

        // 기기 세션 단일화(동일 앱에서 다른 기기 로그인 차단)
        var existing = sessionRepository.findByUserAndClientType(user, clientType);
        if (existing.isPresent()) {
            var s = existing.get();
            boolean stillValid = !s.isRevoked() && s.getExpiresAt().isAfter(LocalDateTime.now());
            if (stillValid && !s.getDeviceId().equals(deviceId)) {
                log.warn("로그인 실패 - 다른 기기에서 이미 로그인 중: userid={}, app={}, existingDevice={}, requestDevice={}",
                        req.getUserid(), clientType, s.getDeviceId(), deviceId);
                return ResponseEntity.status(409)
                        .header("X-Reason", "ALREADY_LOGGED_IN_OTHER_DEVICE")
                        .build();
            }
        }

        // 토큰 발급 + 세션 업서트
        String access  = tokenProvider.generateAccessToken(user.getUserid(), role, clientType);
        String refresh = tokenProvider.generateRefreshToken(user.getUserid(), role, clientType);
        upsertSession(user, clientType, deviceId, refresh);

        // 메타 업데이트
        var now = LocalDateTime.now();
        user.setLastLoginAt(now);
        user.setLastRefreshAt(now);
        userRepository.save(user);

        log.info("관리자 로그인 성공: userid={}, role={}, app={}, device={}", req.getUserid(), role, clientType, deviceId);
        return ResponseEntity.ok(new AuthResponse(access, refresh, "Bearer", role));
    }

    // ── Admin-only: 관리자에 의한 계정 생성(자체 회원가입 없음) ───────────────
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/register")
    public ResponseEntity<?> adminRegister(@Validated @RequestBody AdminRegisterRequest req,
                                           Authentication auth) {
        // 필요 시 이중 방어(클라이언트 헤더/프록시에서 보증): ADMIN_APP + ROLE_ADMIN 만 허용
        // @PreAuthorize로 이미 ROLE_ADMIN 보장됨.

        // 1) 정규화
        String userid = normalizeUserid(req.getUserid());

        // 2) 중복 검사
        if (userRepository.existsByUserid(userid)) {
            return ResponseEntity.status(409).body(Map.of("ok", false, "reason", "DUPLICATE_USERID"));
        }

        // 3) 역할 및 승인 상태 기본값
        Role role = (req.getRole() == null) ? Role.ROLE_USER : req.getRole();
        ApprovalStatus approval = null;
        if (role == Role.ROLE_DRIVER) {
            approval = (req.getApprovalStatus() == null) ? ApprovalStatus.PENDING : req.getApprovalStatus();
        }

        var user = UserEntity.builder()
                .userid(userid)
                .username(req.getUsername() == null ? null : req.getUsername().trim())
                // 이메일/전화/회사/프로필 미사용 → 모두 null
                .role(role)
                .approvalStatus(approval)
                .password(passwordEncoder.encode(req.getPassword()))
                .build();

        userRepository.save(user);

        return ResponseEntity.created(URI.create("/admin/users/" + user.getUserid()))
                .body(Map.of("ok", true, "userid", user.getUserid()));
    }

    // DTO
    @Data
    public static class AdminRegisterRequest {
        @NotBlank @Size(min = 4, max = 50)
        private String userid;

        @NotBlank @Size(min = 8, max = 100)
        private String password;

        @Size(max = 100)
        private String username;

        private Role role; // ROLE_USER / ROLE_DRIVER / ROLE_ADMIN
        private ApprovalStatus approvalStatus; // ROLE_DRIVER일 때만 의미
    }

    // ── Admin-only: REFRESH ────────────────────────────────────────────────────
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            @RequestParam("refreshToken") String refreshToken,
            @RequestParam("clientType")   String clientType,
            @RequestParam("deviceId")     String deviceId
    ) {
        if (!tokenProvider.validate(refreshToken))
            throw new BadCredentialsException("Refresh token invalid");

        String userid = tokenProvider.getUserid(refreshToken);
        var user = userRepository.findByUserid(userid)
                .orElseThrow(() -> new BadCredentialsException("User not found"));

        var sessionOpt = sessionRepository
                .findByUserAndClientTypeAndDeviceIdAndRevokedIsFalseAndExpiresAtAfter(
                        user, clientType, deviceId, LocalDateTime.now());
        if (sessionOpt.isEmpty())
            throw new BadCredentialsException("Session not found or expired");

        var session = sessionOpt.get();

        // 절대 수명 초과
        if (isAbsoluteCapExceeded(session)) {
            session.setRevoked(true);
            sessionRepository.save(session);
            throw new BadCredentialsException("Session absolute lifetime exceeded");
        }

        // refresh 재사용/위조 감지
        String presentedHash = com.example.backend.service.HashUtils.sha256Hex(refreshToken);
        if (!presentedHash.equals(session.getRefreshTokenHash())) {
            log.warn("리프레시 토큰 재사용/위조 감지: userid={}, app={}, device={}", userid, clientType, deviceId);
            session.setRevoked(true);
            sessionRepository.save(session);
            throw new BadCredentialsException("Refresh token mismatch");
        }

        // 관리자 권한 확인
        final String role = user.getRole().name();
        if (!isAllowed(clientType, role)) {
            throw new BadCredentialsException("Role not allowed for this app");
        }

        // 회전
        String newAccess  = tokenProvider.generateAccessToken(userid, role, clientType);
        String newRefresh = tokenProvider.generateRefreshToken(userid, role, clientType);
        rotateSession(session, newRefresh);

        user.setLastRefreshAt(LocalDateTime.now());
        userRepository.save(user);

        return ResponseEntity.ok(new AuthResponse(newAccess, newRefresh, "Bearer", role));
    }

    // ── Admin-only: LOGOUT ─────────────────────────────────────────────────────
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody @Validated LogoutRequest req) {
        if (!tokenProvider.validate(req.getRefreshToken())) {
            log.warn("로그아웃 실패 - refreshToken 파싱 불가");
            return ResponseEntity.status(400).body(Map.of("ok", false, "reason", "INVALID_REFRESH_TOKEN"));
        }

        String userid = tokenProvider.getUserid(req.getRefreshToken());
        var user = userRepository.findByUserid(userid).orElse(null);
        if (user == null) {
            log.warn("로그아웃 실패 - 사용자 없음: useridFromToken={}", userid);
            return ResponseEntity.status(400).body(Map.of("ok", false, "reason", "USER_NOT_FOUND"));
        }

        var sessionOpt = sessionRepository.findByUserAndClientTypeAndDeviceId(
                user, req.getClientType(), req.getDeviceId());
        if (sessionOpt.isEmpty()) {
            log.warn("로그아웃 실패 - 세션 없음: userid={}, app={}, device={}", userid, req.getClientType(), req.getDeviceId());
            return ResponseEntity.status(400).body(Map.of("ok", false, "reason", "SESSION_NOT_FOUND"));
        }

        var session = sessionOpt.get();
        String hash = com.example.backend.service.HashUtils.sha256Hex(req.getRefreshToken());
        if (!hash.equals(session.getRefreshTokenHash())) {
            log.warn("로그아웃 실패 - refreshToken 불일치: userid={}, app={}, device={}", userid, req.getClientType(), req.getDeviceId());
            return ResponseEntity.status(400).body(Map.of("ok", false, "reason", "REFRESH_TOKEN_MISMATCH"));
        }

        session.setRevoked(true);
        sessionRepository.save(session);
        log.info("로그아웃 성공: userid={}, app={}, device={}", userid, req.getClientType(), req.getDeviceId());
        return ResponseEntity.ok(Map.of("ok", true, "message", "LOGGED_OUT"));
    }

    // ── Admin-only: 현재 비밀번호 확인 ──────────────────────────────────────────
    @Data
    static class VerifyCurrentPasswordRequest {
        @NotBlank
        private String currentPassword;
        private String clientType; // 기록/감사용
        private String deviceId;   // 기록/감사용
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/verify-current-password")
    public ResponseEntity<?> verifyCurrentPassword(Authentication authentication,
                                                   @RequestBody @Validated VerifyCurrentPasswordRequest req) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(401).body(Map.of("ok", false, "reason", "UNAUTHORIZED"));
        }

        String userid = (String) authentication.getPrincipal();
        var user = userRepository.findByUserid(userid).orElse(null);
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("ok", false, "reason", "USER_NOT_FOUND"));
        }

        if (user.getRole() != Role.ROLE_ADMIN) {
            return ResponseEntity.status(403).body(Map.of("ok", false, "reason", "FORBIDDEN"));
        }

        if (!passwordEncoder.matches(req.getCurrentPassword(), user.getPassword())) {
            return ResponseEntity.status(400).body(Map.of("ok", false, "reason", "BAD_CURRENT_PASSWORD"));
        }

        log.info("verify-current-password OK: userid={}, clientType={}, deviceId={}",
                userid, req.getClientType(), req.getDeviceId());
        return ResponseEntity.ok(Map.of("ok", true));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────
    /** 관리자 전용: ADMIN_APP + ROLE_ADMIN 만 허용 */
    private boolean isAllowed(String clientType, String role) {
        return "ADMIN_APP".equals(clientType) && "ROLE_ADMIN".equals(role);
    }

    private static String normalizeUserid(String raw) {
        return raw == null ? null : raw.trim().toLowerCase();
    }

    private void upsertSession(UserEntity user, String clientType, String deviceId, String refreshToken) {
        var now = LocalDateTime.now();
        var exp = now.plusDays(refreshExpDays);

        var opt = sessionRepository.findByUserAndClientType(user, clientType);
        if (opt.isPresent()) {
            var s = opt.get();
            s.setDeviceId(deviceId);
            s.setRefreshTokenHash(com.example.backend.service.HashUtils.sha256Hex(refreshToken));
            s.setExpiresAt(applyAbsoluteCapIfNeeded(s, exp));
            s.setRevoked(false);
            sessionRepository.save(s);
        } else {
            var s = UserSession.builder()
                    .user(user)
                    .clientType(clientType)
                    .deviceId(deviceId)
                    .refreshTokenHash(com.example.backend.service.HashUtils.sha256Hex(refreshToken))
                    .expiresAt(exp)
                    .revoked(false)
                    .build();
            sessionRepository.save(s);
            if (refreshAbsoluteMaxDays > 0) {
                s.setExpiresAt(applyAbsoluteCapIfNeeded(s, s.getExpiresAt()));
                sessionRepository.save(s);
            }
        }
    }

    private void rotateSession(UserSession s, String newRefreshToken) {
        if (isAbsoluteCapExceeded(s)) {
            s.setRevoked(true);
            sessionRepository.save(s);
            throw new BadCredentialsException("Session absolute lifetime exceeded");
        }
        var now = LocalDateTime.now();
        s.setRefreshTokenHash(com.example.backend.service.HashUtils.sha256Hex(newRefreshToken));
        var desiredExp = now.plusDays(refreshExpDays);
        s.setExpiresAt(applyAbsoluteCapIfNeeded(s, desiredExp));
        sessionRepository.save(s);
    }

    private LocalDateTime applyAbsoluteCapIfNeeded(UserSession s, LocalDateTime desiredExp) {
        if (refreshAbsoluteMaxDays <= 0) return desiredExp;
        var capEnd = s.getCreatedAt().plusDays(refreshAbsoluteMaxDays);
        return desiredExp.isAfter(capEnd) ? capEnd : desiredExp;
    }

    private boolean isAbsoluteCapExceeded(UserSession s) {
        if (refreshAbsoluteMaxDays <= 0) return false;
        var capEnd = s.getCreatedAt().plusDays(refreshAbsoluteMaxDays);
        return LocalDateTime.now().isAfter(capEnd);
    }
}
