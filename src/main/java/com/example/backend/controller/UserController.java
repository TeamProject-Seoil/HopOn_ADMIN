// src/main/java/com/example/backend/controller/UserController.java
package com.example.backend.controller;

import com.example.backend.dto.ChangePasswordRequest;
import com.example.backend.dto.UserResponse;
import com.example.backend.dto.VerifyPasswordRequest;
import com.example.backend.entity.UserEntity;
import com.example.backend.repository.UserRepository;
import com.example.backend.repository.UserSessionRepository;
import com.example.backend.security.PasswordPolicy;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Validated
public class UserController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserSessionRepository sessionRepository;

    // ─────────────────────────────────────────────────────────────────────────
    // 내 정보 조회
    // ─────────────────────────────────────────────────────────────────────────
    @GetMapping("/me")
    public ResponseEntity<UserResponse> me(Authentication authentication) {
        String userid = (String) authentication.getPrincipal();
        UserEntity u = userRepository.findByUserid(userid).orElseThrow();

        LocalDateTime last = mostRecent(u.getLastLoginAt(), u.getLastRefreshAt());
        return ResponseEntity.ok(toResponse(u, last));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 설정 진입 전 비밀번호 확인
    // ─────────────────────────────────────────────────────────────────────────
    @PostMapping("/me/verify-password")
    public ResponseEntity<?> verifyPassword(Authentication authentication,
                                            @RequestBody @Valid VerifyPasswordRequest req) {
        String userid = (String) authentication.getPrincipal();
        var u = userRepository.findByUserid(userid).orElseThrow();

        boolean ok = passwordEncoder.matches(req.getPassword(), u.getPassword());
        if (!ok) {
            return ResponseEntity.status(400).body(Map.of("ok", false, "reason", "BAD_PASSWORD"));
        }
        return ResponseEntity.ok(Map.of("ok", true));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 비밀번호 변경 (현재 비번 확인 + 정책 검사 + 세션 전체 무효화)
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

        // 모든 세션 무효화
        var sessions = sessionRepository.findByUserAndRevokedIsFalse(u);
        sessions.forEach(s -> s.setRevoked(true));
        if (!sessions.isEmpty()) sessionRepository.saveAll(sessions);

        return ResponseEntity.ok(Map.of("ok", true));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 이름(표시명) 변경
    // ─────────────────────────────────────────────────────────────────────────
    @PutMapping("/me/name")
    public ResponseEntity<?> changeName(Authentication authentication,
                                        @RequestBody @Valid ChangeNameRequest req) {
        String userid = (String) authentication.getPrincipal();
        var u = userRepository.findByUserid(userid).orElseThrow();

        String newName = req.getUsername().trim();
        if (newName.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("ok", false, "reason", "EMPTY_NAME"));
        }
        if (newName.length() > 100) {
            return ResponseEntity.badRequest().body(Map.of("ok", false, "reason", "NAME_TOO_LONG"));
        }

        u.setUsername(newName);
        userRepository.save(u);
        return ResponseEntity.ok(Map.of("ok", true, "username", newName));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 프로필 이미지 업로드 (PNG/JPEG, 최대 2MB)
    // ─────────────────────────────────────────────────────────────────────────
    @PostMapping(value = "/me/profile-image", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> uploadProfileImage(Authentication authentication,
                                                @RequestPart("file") MultipartFile file) throws Exception {
        String userid = (String) authentication.getPrincipal();
        var u = userRepository.findByUserid(userid).orElseThrow();

        if (file == null || file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("ok", false, "reason", "EMPTY_FILE"));
        }

        String ct = file.getContentType();
        if (ct == null || !(ct.equalsIgnoreCase("image/png") || ct.equalsIgnoreCase("image/jpeg"))) {
            return ResponseEntity.status(415).body(Map.of("ok", false, "reason", "UNSUPPORTED_TYPE"));
        }

        long max = 2L * 1024 * 1024; // 2MB
        if (file.getSize() > max) {
            return ResponseEntity.status(413).body(Map.of("ok", false, "reason", "FILE_TOO_LARGE", "max", max));
        }

        u.setProfileImage(file.getBytes());
        userRepository.save(u);
        return ResponseEntity.ok(Map.of("ok", true));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 프로필 이미지 다운로드
    // ─────────────────────────────────────────────────────────────────────────
    @GetMapping("/me/profile-image")
    public ResponseEntity<byte[]> downloadProfileImage(Authentication authentication) {
        String userid = (String) authentication.getPrincipal();
        var u = userRepository.findByUserid(userid).orElseThrow();

        byte[] img = u.getProfileImage();
        if (img == null || img.length == 0) {
            return ResponseEntity.status(404).build();
        }

        String filename = URLEncoder.encode((u.getUsername() != null ? u.getUsername() : u.getUserid()) + ".jpg",
                StandardCharsets.UTF_8);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.IMAGE_JPEG); // 저장 타입 구분 안했으니 통일. 필요시 감지 로직 추가
        headers.setContentLength(img.length);
        headers.set(HttpHeaders.CONTENT_DISPOSITION, "inline; filename*=UTF-8''" + filename);
        headers.setCacheControl(CacheControl.noCache().getHeaderValue());

        return new ResponseEntity<>(img, headers, HttpStatus.OK);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 프로필 이미지 삭제
    // ─────────────────────────────────────────────────────────────────────────
    @DeleteMapping("/me/profile-image")
    public ResponseEntity<?> removeProfileImage(Authentication authentication) {
        String userid = (String) authentication.getPrincipal();
        var u = userRepository.findByUserid(userid).orElseThrow();

        u.setProfileImage(null);
        userRepository.save(u);
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

    private UserResponse toResponse(UserEntity u, LocalDateTime last) {
        return UserResponse.builder()
                .userNum(u.getUserNum())
                .userid(u.getUserid())
                .username(u.getUsername())
                .email(u.getEmail())
                .tel(u.getTel())
                .company(u.getCompany())
                .role(u.getRole())
                .approvalStatus(u.getApprovalStatus())
                .hasProfileImage(u.getProfileImage() != null && u.getProfileImage().length > 0)
                .hasDriverLicenseFile(false)
                .createdAtIso(UserResponse.toIsoOrNull(u.getCreatedAt()))
                .lastLoginAtIso(UserResponse.toIsoOrNull(last))
                .build();
    }

    // 이름 변경용 간단 DTO (컨트롤러 내부 정의)
    public static class ChangeNameRequest {
        @NotBlank
        public String username;
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
    }
}
