// src/main/java/com/example/backend/controller/AdminUserController.java
package com.example.backend.controller;

import com.example.backend.entity.ApprovalStatus;
import com.example.backend.entity.Role;
import com.example.backend.entity.UserEntity;
import com.example.backend.repository.UserRepository;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Map;

@RestController
@RequestMapping("/admin/users")
@RequiredArgsConstructor
@Validated
public class AdminUserController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // ─────────────────────────────────────────────────────────────────────
    // 관리자: 계정 생성 (관리자는 관리자도 생성 가능)
    // ─────────────────────────────────────────────────────────────────────
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> create(@Validated @RequestBody AdminCreateUserRequest req) {
        String userid = normalizeUserid(req.getUserid());

        // userid만 중복 검사
        if (userRepository.existsByUserid(userid)) {
            return ResponseEntity.status(409).body(Map.of("ok", false, "reason", "DUPLICATE_USERID"));
        }

        Role role = (req.getRole() == null) ? Role.ROLE_USER : req.getRole();
        ApprovalStatus approval = null;
        if (role == Role.ROLE_DRIVER) {
            approval = (req.getApprovalStatus() == null) ? ApprovalStatus.PENDING : req.getApprovalStatus();
        }

        var user = UserEntity.builder()
                .userid(userid)
                .password(passwordEncoder.encode(req.getPassword()))
                .username(req.getUsername() == null ? null : req.getUsername().trim())
                .role(role)
                .approvalStatus(approval)
                .build();

        userRepository.save(user);

        return ResponseEntity
                .created(URI.create("/admin/users/" + user.getUserid()))
                .body(Map.of("ok", true, "userid", user.getUserid()));
    }

    // ─────────────────────────────────────────────────────────────────────
    // 관리자: 계정 삭제 (본인 삭제 금지 + 마지막 관리자 보호)
    // ─────────────────────────────────────────────────────────────────────
    @DeleteMapping("/{userid}")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> deleteUser(@PathVariable String userid, Authentication auth) {
        String target = normalizeUserid(userid);
        String actor  = normalizeUserid((String) auth.getPrincipal());

        var userOpt = userRepository.findByUserid(target);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(404).body(Map.of("ok", false, "reason", "NOT_FOUND"));
        }
        var u = userOpt.get();

        // 1) 본인 삭제 금지
        if (actor != null && actor.equals(target)) {
            return ResponseEntity.status(403).body(Map.of("ok", false, "reason", "CANNOT_DELETE_SELF"));
        }

        // 2) 마지막 ADMIN 보호
        if (u.getRole() == Role.ROLE_ADMIN) {
            long admins = userRepository.findAll().stream()
                    .filter(x -> x.getRole() == Role.ROLE_ADMIN)
                    .count();
            if (admins <= 1) {
                return ResponseEntity.status(409).body(Map.of("ok", false, "reason", "LAST_ADMIN_PROTECTED"));
            }
        }

        int affected = userRepository.hardDeleteByUserid(target);
        if (affected == 0) {
            return ResponseEntity.status(404).body(Map.of("ok", false, "reason", "NOT_FOUND"));
        }
        return ResponseEntity.ok(Map.of("ok", true, "message", "DELETED", "userid", target));
    }

    // ─────────────────────────────────────────────────────────────────────
    // 관리자: 다른 사용자 비밀번호 초기화
    //  - 본인 계정에는 사용하지 말 것(위 정책 준수)
    // ─────────────────────────────────────────────────────────────────────
    @PostMapping("/{userid}/reset-password")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> adminResetPassword(@PathVariable String userid,
                                                @RequestBody @Validated AdminResetPasswordRequest req,
                                                Authentication auth) {
        String target = normalizeUserid(userid);
        String actor  = normalizeUserid((String) auth.getPrincipal());

        var userOpt = userRepository.findByUserid(target);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(404).body(Map.of("ok", false, "reason", "NOT_FOUND"));
        }
        // 원칙상 본인 계정 초기화 금지(자가 변경은 /users/me/password 사용)
        if (actor != null && actor.equals(target)) {
            return ResponseEntity.status(403).body(Map.of("ok", false, "reason", "CANNOT_RESET_SELF"));
        }

        var u = userOpt.get();
        u.setPassword(passwordEncoder.encode(req.getNewPassword()));
        userRepository.save(u);

        // (선택) 세션 무효화는 여기서 하지 않음 — 정책에 따라 필요하면 추가 가능
        return ResponseEntity.ok(Map.of("ok", true));
    }

    // ─────────────────────────────────────────────────────────────────────
    // 내부 헬퍼/DTO
    // ─────────────────────────────────────────────────────────────────────
    private static String normalizeUserid(String raw) {
        return raw == null ? null : raw.trim().toLowerCase();
    }

    @Data
    public static class AdminCreateUserRequest {
        @NotBlank @Size(min = 4, max = 50)
        private String userid;

        @NotBlank @Size(min = 8, max = 100)
        private String password;

        @Size(max = 100)
        private String username;

        private Role role; // ROLE_USER / ROLE_DRIVER / ROLE_ADMIN
        private ApprovalStatus approvalStatus; // ROLE_DRIVER 일 때만 사용
    }

    @Data
    public static class AdminResetPasswordRequest {
        @NotBlank @Size(min = 8, max = 100)
        private String newPassword;
    }
}
