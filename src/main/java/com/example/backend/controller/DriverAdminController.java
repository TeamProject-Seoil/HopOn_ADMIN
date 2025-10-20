// src/main/java/com/example/backend/controller/DriverAdminController.java
package com.example.backend.controller;

import com.example.backend.dto.UserResponse;
import com.example.backend.entity.ApprovalStatus;
import com.example.backend.entity.Role;
import com.example.backend.entity.UserEntity;
import com.example.backend.repository.DriverLicenseRepository;
import com.example.backend.repository.UserRepository;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.*;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/admin/drivers")
@RequiredArgsConstructor
public class DriverAdminController {

    private final UserRepository userRepository;
    private final DriverLicenseRepository driverLicenseRepository;

    // ─────────────────────────────────────────────────────────────────────────────
    // 대기중 드라이버 목록 (페이징 + 검색(userid/username 포함))
    // 예: GET /admin/drivers/pending?page=0&size=20&sort=userid,asc&search=kim
    // ─────────────────────────────────────────────────────────────────────────────
    @GetMapping("/pending")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserResponse>> listPending(
            @RequestParam(value = "search", required = false) String search,
            Pageable pageable
    ) {
        // 기본 정렬 보정
        Pageable pg = pageable;
        if (pg.getSort().isUnsorted()) {
            pg = PageRequest.of(
                    Math.max(0, pageable.getPageNumber()),
                    Math.max(1, pageable.getPageSize()),
                    Sort.by(Sort.Order.asc("userid"))
            );
        }

        // PENDING 드라이버 페이지 조회
        Page<UserEntity> rawPage = userRepository.findByRoleAndApprovalStatus(Role.ROLE_DRIVER, ApprovalStatus.PENDING, pg);

        // 검색어가 있으면 메모리에서 간단 필터(userid/username만)
        if (StringUtils.hasText(search)) {
            String q = search.trim().toLowerCase();
            List<UserEntity> filtered = rawPage.getContent().stream()
                    .filter(u -> containsIgnoreCase(u.getUserid(), q)
                            || containsIgnoreCase(u.getUsername(), q))
                    .collect(Collectors.toList());

            Page<UserEntity> filteredPage = new PageImpl<>(filtered, pg, filtered.size());
            Page<UserResponse> mapped = filteredPage.map(this::toResponse);
            return ResponseEntity.ok(mapped);
        }

        Page<UserResponse> mapped = rawPage.map(this::toResponse);
        return ResponseEntity.ok(mapped);
    }

    private static boolean containsIgnoreCase(String s, String qLower) {
        return s != null && s.toLowerCase().contains(qLower);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 라이선스 이미지 조회 (inline 미리보기)
    // ─────────────────────────────────────────────────────────────────────────────
    @GetMapping("/{userid}/license")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<byte[]> getLicense(@PathVariable String userid) {
        var u = userRepository.findByUserid(userid).orElse(null);
        if (u == null) return notFound();

        var dl = driverLicenseRepository.findByUser_UserNum(u.getUserNum()).orElse(null);
        if (dl == null || dl.getLicenseImage() == null || dl.getLicenseImage().length == 0) {
            return notFound();
        }

        byte[] bytes = dl.getLicenseImage();
        String contentType = MimeSniffer.guessImageContentType(bytes); // 간단 MIME 추론
        String filename = "license-" + userid + MimeSniffer.extFor(contentType);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType(contentType));
        headers.setContentLength(bytes.length);
        headers.setContentDisposition(ContentDisposition.inline()
                .filename(encodeFilename(filename))
                .build());

        return new ResponseEntity<>(bytes, headers, HttpStatus.OK);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 승인 (PENDING → APPROVED)
    // ─────────────────────────────────────────────────────────────────────────────
    @PostMapping("/{userid}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> approve(@PathVariable String userid) {
        var u = userRepository.findByUserid(userid).orElse(null);
        if (u == null) return notFound();

        if (u.getRole() != Role.ROLE_DRIVER) {
            return badRequest("NOT_A_DRIVER");
        }
        if (u.getApprovalStatus() != ApprovalStatus.PENDING) {
            return conflict("INVALID_STATUS", Map.of("current", u.getApprovalStatus().name()));
        }

        u.setApprovalStatus(ApprovalStatus.APPROVED);
        userRepository.save(u);
        return ok(Map.of("ok", true, "status", "APPROVED"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 거절 (PENDING → REJECTED) + optional 사유
    // ─────────────────────────────────────────────────────────────────────────────
    @Data
    public static class RejectRequest {
        private String reason; // optional
    }

    @PostMapping("/{userid}/reject")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> reject(@PathVariable String userid,
                                    @RequestBody(required = false) RejectRequest body) {
        var u = userRepository.findByUserid(userid).orElse(null);
        if (u == null) return notFound();

        if (u.getRole() != Role.ROLE_DRIVER) {
            return badRequest("NOT_A_DRIVER");
        }
        if (u.getApprovalStatus() != ApprovalStatus.PENDING) {
            return conflict("INVALID_STATUS", Map.of("current", u.getApprovalStatus().name()));
        }

        u.setApprovalStatus(ApprovalStatus.REJECTED);
        // 필요 시: u.setRejectReason(StringUtils.hasText(body?.reason) ? body.reason.trim() : null);
        userRepository.save(u);

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("ok", true);
        resp.put("status", "REJECTED");
        if (body != null && StringUtils.hasText(body.getReason())) {
            resp.put("reason", body.getReason().trim());
        }
        return ok(resp);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 내부: 매핑/유틸
    // ─────────────────────────────────────────────────────────────────────────────
    private UserResponse toResponse(UserEntity u) {
        boolean hasDl = driverLicenseRepository.existsByUser_UserNum(u.getUserNum());
        return UserResponse.builder()
                .userNum(u.getUserNum())
                .userid(u.getUserid())
                .username(u.getUsername())
                .role(u.getRole())
                .approvalStatus(u.getApprovalStatus())
                .hasDriverLicenseFile(hasDl)
                .build();
    }

    private static String encodeFilename(String filename) {
        return URLEncoder.encode(filename, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static ResponseEntity<byte[]> notFound() {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
    }

    private static ResponseEntity<Map<String, Object>> ok(Map<String, Object> body) {
        return ResponseEntity.ok(body);
    }

    private static ResponseEntity<Map<String, Object>> badRequest(String reason) {
        return ResponseEntity.badRequest().body(Map.of("ok", false, "reason", reason));
    }

    private static ResponseEntity<Map<String, Object>> conflict(String reason, Map<String, ?> extra) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", false);
        body.put("reason", reason);
        if (extra != null) body.putAll(extra);
        return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
    }
}

/**
 * 매우 단순한 이미지 MIME 스니퍼 (JPEG/PNG/GIF만 식별, 그 외는 application/octet-stream)
 * 필요 시 별도 파일로 빼서 재사용하세요.
 */
final class MimeSniffer {
    private MimeSniffer() {}

    static String guessImageContentType(byte[] b) {
        if (b == null || b.length < 4) return MediaType.APPLICATION_OCTET_STREAM_VALUE;

        // JPEG: FF D8 FF
        if ((b[0] & 0xFF) == 0xFF && (b[1] & 0xFF) == 0xD8 && (b[2] & 0xFF) == 0xFF) {
            return MediaType.IMAGE_JPEG_VALUE;
        }
        // PNG: 89 50 4E 47
        if ((b[0] & 0xFF) == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47) {
            return MediaType.IMAGE_PNG_VALUE;
        }
        // GIF: 47 49 46 38
        if (b[0] == 0x47 && b[1] == 0x49 && b[2] == 0x46 && b[3] == 0x38) {
            return MediaType.IMAGE_GIF_VALUE;
        }
        return MediaType.APPLICATION_OCTET_STREAM_VALUE;
    }

    static String extFor(String ct) {
        if (MediaType.IMAGE_JPEG_VALUE.equals(ct)) return ".jpg";
        if (MediaType.IMAGE_PNG_VALUE.equals(ct))  return ".png";
        if (MediaType.IMAGE_GIF_VALUE.equals(ct))  return ".gif";
        return ".bin";
    }
}
