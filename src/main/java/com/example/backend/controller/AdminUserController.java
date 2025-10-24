package com.example.backend.controller;

import com.example.backend.entity.ApprovalStatus;
import com.example.backend.entity.Role;
import com.example.backend.entity.UserEntity;
import com.example.backend.entity.UserSession;
import com.example.backend.repository.UserRepository;
import com.example.backend.repository.UserSessionRepository;
import com.example.backend.security.PasswordPolicy;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.domain.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StreamUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/admin/users")
@RequiredArgsConstructor
@Validated
public class AdminUserController {

    private final UserRepository userRepository;
    private final UserSessionRepository sessionRepository;
    private final PasswordEncoder passwordEncoder;

    // ─────────────────────────────────────────────────────────────────────
    // 0) 아이디 중복확인 API
    // GET /admin/users/exists?userid=...
    // ─────────────────────────────────────────────────────────────────────
    @GetMapping("/exists")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> exists(@RequestParam("userid") String userid) {
        String id = normalizeUserid(userid);
        boolean ex = (id != null && !id.isBlank()) && userRepository.existsByUseridIgnoreCase(id);
        return ResponseEntity.ok(Map.of("exists", ex));
    }

    // ─────────────────────────────────────────────────────────────────────
    // 1) 목록 조회 (역할/승인상태/검색/페이지)
    // ─────────────────────────────────────────────────────────────────────
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<AdminListItem>> list(
            @RequestParam(value = "role", required = false) Role role,
            @RequestParam(value = "status", required = false) ApprovalStatus status,
            @RequestParam(value = "q", required = false) String q,
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "20") int size,
            @RequestParam(value = "sort", defaultValue = "createdAt,desc") String sort) {

        Pageable pageable = toPageable(sort, page, size);

        Page<UserEntity> pageData;
        if (role != null && status != null) {
            pageData = userRepository.searchByRoleAndStatus(role, status, norm(q), pageable);
        } else if (role != null) {
            pageData = userRepository.findAll(pageable);
            List<UserEntity> filtered = pageData.getContent().stream()
                    .filter(u -> u.getRole() == role)
                    .filter(u -> isMatch(u, norm(q)))
                    .collect(Collectors.toList());
            pageData = new PageImpl<>(filtered, pageable, filtered.size());
        } else {
            pageData = userRepository.findAll(pageable);
            List<UserEntity> filtered = pageData.getContent().stream()
                    .filter(u -> isMatch(u, norm(q)))
                    .collect(Collectors.toList());
            pageData = new PageImpl<>(filtered, pageable, filtered.size());
        }

        Map<Long, Boolean> loggedInMap = markLoggedInFor(pageData.getContent());

        Page<AdminListItem> result = pageData
                .map(u -> AdminListItem.from(u, loggedInMap.getOrDefault(u.getUserNum(), false)));
        return ResponseEntity.ok(result);
    }

    private boolean isMatch(UserEntity u, String q) {
        if (q == null || q.isBlank())
            return true;
        String uid = Optional.ofNullable(u.getUserid()).orElse("").toLowerCase();
        String uname = Optional.ofNullable(u.getUsername()).orElse("").toLowerCase();
        return uid.contains(q) || uname.contains(q);
    }

    private Map<Long, Boolean> markLoggedInFor(List<UserEntity> users) {
        Map<Long, Boolean> map = new HashMap<>();
        if (users.isEmpty())
            return map;
        LocalDateTime now = LocalDateTime.now();
        for (UserEntity u : users) {
            boolean anyActive = sessionRepository
                    .findByUserAndRevokedIsFalseAndExpiresAtAfter(u, now)
                    .stream().findAny().isPresent();
            map.put(u.getUserNum(), anyActive);
        }
        return map;
    }

    private Pageable toPageable(String sort, int page, int size) {
        Sort s;
        if (sort != null && sort.contains(",")) {
            String[] t = sort.split(",", 2);
            s = "desc".equalsIgnoreCase(t[1]) ? Sort.by(t[0]).descending() : Sort.by(t[0]).ascending();
        } else {
            s = Sort.by("createdAt").descending();
        }
        return PageRequest.of(Math.max(0, page), Math.min(Math.max(1, size), 100), s);
    }

    private String norm(String s) {
        return s == null ? null : s.trim().toLowerCase();
    }

    private static String normalizeUserid(String raw) {
        return raw == null ? null : raw.trim().toLowerCase();
    }

    // ─────────────────────────────────────────────────────────────────────
    // 2) 상세 + 세션 목록
    // ─────────────────────────────────────────────────────────────────────
    @GetMapping("/{userid}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDetailResp> detail(@PathVariable String userid) {
        String id = norm(userid);
        var u = userRepository.findByUserid(id).orElse(null);
        if (u == null)
            return ResponseEntity.status(404).body(null);

        LocalDateTime now = LocalDateTime.now();
        var sessions = sessionRepository.findByUserOrderByUpdatedAtDesc(u).stream()
                .map(AdminSessionDto::from)
                .toList();

        boolean loggedIn = sessionRepository
                .findByUserAndRevokedIsFalseAndExpiresAtAfter(u, now)
                .stream().findAny().isPresent();

        return ResponseEntity.ok(UserDetailResp.from(u, loggedIn, sessions));
    }

    // ─────────────────────────────────────────────────────────────────────
    // 3) 특정 세션 로그아웃
    // ─────────────────────────────────────────────────────────────────────
    @PostMapping("/{userid}/sessions/{sessionId}/revoke")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> revokeOne(@PathVariable String userid, @PathVariable Long sessionId) {
        String id = norm(userid);
        var user = userRepository.findByUserid(id).orElse(null);
        if (user == null)
            return ResponseEntity.status(404).body(Map.of("ok", false, "reason", "USER_NOT_FOUND"));

        var sOpt = sessionRepository.findByIdAndUser(sessionId, user);
        if (sOpt.isEmpty())
            return ResponseEntity.status(404).body(Map.of("ok", false, "reason", "SESSION_NOT_FOUND"));

        var s = sOpt.get();
        s.setRevoked(true);
        sessionRepository.save(s);
        return ResponseEntity.ok(Map.of("ok", true));
    }

    // ─────────────────────────────────────────────────────────────────────
    // 4) 모든 활성 세션 로그아웃
    // ─────────────────────────────────────────────────────────────────────
    @PostMapping("/{userid}/sessions/revoke-all")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> revokeAll(@PathVariable String userid) {
        String id = norm(userid);
        var user = userRepository.findByUserid(id).orElse(null);
        if (user == null)
            return ResponseEntity.status(404).body(Map.of("ok", false, "reason", "USER_NOT_FOUND"));

        var actives = sessionRepository.findByUserAndRevokedIsFalse(user);
        actives.forEach(s -> s.setRevoked(true));
        sessionRepository.saveAll(actives);
        return ResponseEntity.ok(Map.of("ok", true, "revoked", actives.size()));
    }

    // ─────────────────────────────────────────────────────────────────────
    // 5) 역할 변경 (자기강등 방지 + 마지막 관리자 보호)
    // ─────────────────────────────────────────────────────────────────────
    @PostMapping("/{userid}/role")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> changeRole(@PathVariable String userid,
            @RequestBody @Validated ChangeRoleReq req,
            Authentication auth) {
        String targetId = norm(userid);
        String actor = norm((String) auth.getPrincipal());
        var userOpt = userRepository.findByUserid(targetId);
        if (userOpt.isEmpty())
            return ResponseEntity.status(404).body(Map.of("ok", false, "reason", "NOT_FOUND"));

        var u = userOpt.get();
        Role newRole = req.getRole();
        if (newRole == null)
            return ResponseEntity.badRequest().body(Map.of("ok", false, "reason", "ROLE_REQUIRED"));

        if (u.getRole() == Role.ROLE_ADMIN && actor != null && actor.equals(targetId)
                && newRole != Role.ROLE_ADMIN) {
            return ResponseEntity.status(403).body(Map.of("ok", false, "reason", "CANNOT_DEMOTE_SELF"));
        }

        if (u.getRole() == Role.ROLE_ADMIN && newRole != Role.ROLE_ADMIN) {
            long admins = userRepository.findAll().stream()
                    .filter(x -> x.getRole() == Role.ROLE_ADMIN)
                    .count();
            if (admins <= 1) {
                return ResponseEntity.status(409).body(Map.of("ok", false, "reason", "LAST_ADMIN_PROTECTED"));
            }
        }

        u.setRole(newRole);
        if (newRole != Role.ROLE_DRIVER)
            u.setApprovalStatus(null);
        userRepository.save(u);

        return ResponseEntity.ok(Map.of("ok", true, "role", newRole.name()));
    }

    @Data
    public static class ChangeRoleReq {
        @NotNull
        private Role role;
    }

    // ─────────────────────────────────────────────────────────────────────
    // 6) 드라이버 승인상태 변경
    // ─────────────────────────────────────────────────────────────────────
    @PostMapping("/{userid}/approval")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> changeApproval(@PathVariable String userid,
            @RequestBody @Validated ChangeApprovalReq req) {
        String id = norm(userid);
        var u = userRepository.findByUserid(id).orElse(null);
        if (u == null)
            return ResponseEntity.status(404).body(Map.of("ok", false, "reason", "NOT_FOUND"));
        if (u.getRole() != Role.ROLE_DRIVER)
            return ResponseEntity.status(400).body(Map.of("ok", false, "reason", "NOT_DRIVER"));

        u.setApprovalStatus(req.getStatus());
        userRepository.save(u);
        return ResponseEntity.ok(Map.of("ok", true, "status", req.getStatus().name()));
    }

    @Data
    public static class ChangeApprovalReq {
        @NotNull
        private ApprovalStatus status;
    }

    // ─────────────────────────────────────────────────────────────────────
    // 7) 계정 생성 — ROLE_ADMIN만 생성 가능
    // + 회사명=HopOn, 승인상태=APPROVED, 기본 프로필 이미지(LONGBLOB) 자동 세팅
    // (classpath: static/profile_image/default_profile_image.jpg)
    // ─────────────────────────────────────────────────────────────────────
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> create(@Validated @RequestBody AdminCreateUserRequest req) {
        String userid = normalizeUserid(req.getUserid());

        if (userRepository.existsByUserid(userid)) {
            return ResponseEntity.status(409).body(Map.of("ok", false, "reason", "DUPLICATE_USERID"));
        }

        // ROLE_ADMIN만 허용
        Role role = req.getRole();
        if (role == null || role != Role.ROLE_ADMIN) {
            return ResponseEntity.status(403).body(Map.of(
                    "ok", false,
                    "reason", "ONLY_ADMIN_CREATION_ALLOWED",
                    "message", "관리자는 ROLE_ADMIN 계정만 생성할 수 있습니다."));
        }

        // 비밀번호 정책 검사 (8~64 & 특수문자 허용)
        String pwReason = PasswordPolicy.validateAndReason(req.getPassword());
        if (pwReason != null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "ok", false,
                    "reason", "PASSWORD_POLICY_VIOLATION",
                    "message", pwReason));
        }

        // 기본 프로필 이미지 로드
        byte[] defaultProfile = null;
        try (var in = new ClassPathResource("static/profile_image/default_profile_image.jpg").getInputStream()) {
            defaultProfile = StreamUtils.copyToByteArray(in);
        } catch (Exception ignore) {
            // 없거나 실패하면 null → 프론트에서 기본 이미지 fallback
        }

        var user = UserEntity.builder()
                .userid(userid)
                .password(passwordEncoder.encode(req.getPassword()))
                .username(req.getUsername() == null ? null : req.getUsername().trim())
                // 🔽 NOT NULL 회피용 자동 이메일
                .email(userid + "@hopon.local")
                .role(Role.ROLE_ADMIN)
                .company("HopOn")
                .approvalStatus(ApprovalStatus.APPROVED)
                .profileImage(defaultProfile)
                .build();

        userRepository.save(user);

        return ResponseEntity
                .created(URI.create("/admin/users/" + user.getUserid()))
                .body(Map.of("ok", true, "userid", user.getUserid(), "role", "ROLE_ADMIN"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // 8) 계정 삭제 (본인 삭제 금지 + 마지막 관리자 보호)
    // ─────────────────────────────────────────────────────────────────────
    @DeleteMapping("/{userid}")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> deleteUser(@PathVariable String userid, Authentication auth) {
        String target = normalizeUserid(userid);
        String actor = normalizeUserid((String) auth.getPrincipal());

        var userOpt = userRepository.findByUserid(target);
        if (userOpt.isEmpty())
            return ResponseEntity.status(404).body(Map.of("ok", false, "reason", "NOT_FOUND"));

        var u = userOpt.get();

        if (actor != null && actor.equals(target))
            return ResponseEntity.status(403).body(Map.of("ok", false, "reason", "CANNOT_DELETE_SELF"));

        if (u.getRole() == Role.ROLE_ADMIN) {
            long admins = userRepository.findAll().stream()
                    .filter(x -> x.getRole() == Role.ROLE_ADMIN)
                    .count();
            if (admins <= 1)
                return ResponseEntity.status(409).body(Map.of("ok", false, "reason", "LAST_ADMIN_PROTECTED"));
        }

        int affected = userRepository.hardDeleteByUserid(target);
        if (affected == 0)
            return ResponseEntity.status(404).body(Map.of("ok", false, "reason", "NOT_FOUND"));
        return ResponseEntity.ok(Map.of("ok", true, "message", "DELETED", "userid", target));
    }

    // ─────────────────────────────────────────────────────────────────────
    // 9) 다른 사용자 비밀번호 초기화 (정책 적용)
    // ─────────────────────────────────────────────────────────────────────
    @PostMapping("/{userid}/reset-password")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> adminResetPassword(@PathVariable String userid,
            @RequestBody @Validated AdminResetPasswordRequest req,
            Authentication auth) {
        String target = normalizeUserid(userid);
        String actor = normalizeUserid((String) auth.getPrincipal());

        var userOpt = userRepository.findByUserid(target);
        if (userOpt.isEmpty())
            return ResponseEntity.status(404).body(Map.of("ok", false, "reason", "NOT_FOUND"));

        if (actor != null && actor.equals(target))
            return ResponseEntity.status(403).body(Map.of("ok", false, "reason", "CANNOT_RESET_SELF"));

        // 정책 검사 (8~64 & 특수문자 허용)
        String pwReason = PasswordPolicy.validateAndReason(req.getNewPassword());
        if (pwReason != null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "ok", false,
                    "reason", "PASSWORD_POLICY_VIOLATION",
                    "message", pwReason));
        }

        var u = userOpt.get();
        u.setPassword(passwordEncoder.encode(req.getNewPassword()));
        userRepository.save(u);
        return ResponseEntity.ok(Map.of("ok", true));
    }

    // ─────────────────────────────────────────────────────────────────────
    // DTO / View Models
    // ─────────────────────────────────────────────────────────────────────
    @Data
    public static class AdminCreateUserRequest {
        @NotBlank
        @Size(min = 4, max = 50)
        private String userid;

        // (수정) 8~64자
        @NotBlank
        @Size(min = 8, max = 64)
        private String password;

        @Size(max = 100)
        private String username;

        private Role role; // ROLE_ADMIN만 허용
        private ApprovalStatus approvalStatus; // 호환성 유지 (사용 안 함)
    }

    @Data
    public static class AdminResetPasswordRequest {
        @NotBlank
        @Size(min = 8, max = 64)
        private String newPassword;
    }

    @Getter
    @Builder
    public static class AdminListItem {
        private Long userNum;
        private String userid;
        private String username;
        private Role role;
        private ApprovalStatus approvalStatus;
        private boolean loggedIn;
        private String createdAtIso;
        private String lastLoginAtIso;

        public static AdminListItem from(UserEntity u, boolean loggedIn) {
            return AdminListItem.builder()
                    .userNum(u.getUserNum())
                    .userid(u.getUserid())
                    .username(u.getUsername())
                    .role(u.getRole())
                    .approvalStatus(u.getApprovalStatus())
                    .loggedIn(loggedIn)
                    .createdAtIso(toIso(u.getCreatedAt()))
                    .lastLoginAtIso(toIso(u.getLastLoginAt()))
                    .build();
        }
    }

    @Getter
    @Builder
    public static class UserDetailResp {
        private Long userNum;
        private String userid;
        private String username;
        private String email;
        private String tel;
        private String company;
        private Role role;
        private ApprovalStatus approvalStatus;
        private String createdAtIso;
        private String lastLoginAtIso;
        private boolean loggedIn;
        private List<AdminSessionDto> sessions;

        public static UserDetailResp from(UserEntity u, boolean loggedIn, List<AdminSessionDto> sessions) {
            return UserDetailResp.builder()
                    .userNum(u.getUserNum())
                    .userid(u.getUserid())
                    .username(u.getUsername())
                    .email(u.getEmail())
                    .tel(u.getTel())
                    .company(u.getCompany())
                    .role(u.getRole())
                    .approvalStatus(u.getApprovalStatus())
                    .createdAtIso(toIso(u.getCreatedAt()))
                    .lastLoginAtIso(toIso(u.getLastLoginAt()))
                    .loggedIn(loggedIn)
                    .sessions(sessions)
                    .build();
        }
    }

    @Getter
    @Builder
    public static class AdminSessionDto {
        private Long id;
        private String clientType; // USER_APP | DRIVER_APP | ADMIN_APP
        private String deviceId;
        private boolean revoked;
        private String expiresAtIso;
        private String createdAtIso;
        private String updatedAtIso;

        public static AdminSessionDto from(UserSession s) {
            return AdminSessionDto.builder()
                    .id(s.getId())
                    .clientType(s.getClientType())
                    .deviceId(s.getDeviceId())
                    .revoked(s.isRevoked())
                    .expiresAtIso(toIso(s.getExpiresAt()))
                    .createdAtIso(toIso(s.getCreatedAt()))
                    .updatedAtIso(toIso(s.getUpdatedAt()))
                    .build();
        }
    }

    private static String toIso(LocalDateTime t) {
        return t == null ? null : t.atZone(java.time.ZoneId.systemDefault()).toInstant().toString();
    }
}
