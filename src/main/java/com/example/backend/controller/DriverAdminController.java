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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.*;
import org.springframework.http.*;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/admin/drivers")
@RequiredArgsConstructor
public class DriverAdminController {

    private final UserRepository userRepository;
    private final DriverLicenseRepository driverLicenseRepository;

    // ✅ 메일 발송을 위한 의존성/설정
    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromAddress;

    @Value("${app.mail.from-name:HopOn Admin}")
    private String fromName;

    private static final ZoneId KST = ZoneId.of("Asia/Seoul");
    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    // ─────────────────────────────────────────────────────────────────────────────
    // 대기중 드라이버 목록 (페이징 + 검색(userid/username) + sort=createdAt,asc|desc)
    // 예: GET /admin/drivers/pending?page=0&size=20&sort=createdAt,asc&search=kim
    // ─────────────────────────────────────────────────────────────────────────────
    @GetMapping("/pending")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserResponse>> listPending(
            @RequestParam(value = "search", required = false) String search,
            Pageable pageable) {
        // 기본 정렬 보정(미지정 시 createdAt ASC)
        Pageable pg = pageable;
        if (pg.getSort().isUnsorted()) {
            pg = PageRequest.of(
                    Math.max(0, pageable.getPageNumber()),
                    Math.max(1, pageable.getPageSize()),
                    Sort.by(Sort.Order.asc("createdAt")));
        }

        Page<UserEntity> rawPage = userRepository.findByRoleAndApprovalStatus(
                Role.ROLE_DRIVER, ApprovalStatus.PENDING, pg);

        // 검색: userid/username 포함
        Page<UserEntity> pageToMap;
        if (StringUtils.hasText(search)) {
            String q = search.trim().toLowerCase();
            List<UserEntity> filtered = rawPage.getContent().stream()
                    .filter(u -> containsIgnoreCase(u.getUserid(), q)
                            || containsIgnoreCase(u.getUsername(), q))
                    .collect(Collectors.toList());
            pageToMap = new PageImpl<>(filtered, pg, filtered.size());
        } else {
            pageToMap = rawPage;
        }

        Page<UserResponse> mapped = pageToMap.map(this::toResponse);
        return ResponseEntity.ok(mapped);
    }

    private static boolean containsIgnoreCase(String s, String qLower) {
        return s != null && s.toLowerCase().contains(qLower);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 프로필 이미지 조회
    // ─────────────────────────────────────────────────────────────────────────────
    @GetMapping("/{userid}/profile")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<byte[]> getProfile(@PathVariable String userid) {
        var u = userRepository.findByUserid(userid).orElse(null);
        if (u == null || u.getProfileImage() == null || u.getProfileImage().length == 0) {
            return notFound();
        }
        byte[] bytes = u.getProfileImage();
        String contentType = MimeSniffer.guessImageContentType(bytes);
        String filename = "profile-" + userid + MimeSniffer.extFor(contentType);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType(contentType));
        headers.setContentLength(bytes.length);
        headers.setContentDisposition(ContentDisposition.inline()
                .filename(encodeFilename(filename))
                .build());
        return new ResponseEntity<>(bytes, headers, HttpStatus.OK);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 라이선스 이미지 조회 (inline 미리보기)
    // ─────────────────────────────────────────────────────────────────────────────
    @GetMapping("/{userid}/license")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<byte[]> getLicense(@PathVariable String userid) {
        var u = userRepository.findByUserid(userid).orElse(null);
        if (u == null)
            return notFound();

        var dl = driverLicenseRepository.findByUser_UserNum(u.getUserNum()).orElse(null);
        if (dl == null || dl.getLicenseImage() == null || dl.getLicenseImage().length == 0) {
            return notFound();
        }

        byte[] bytes = dl.getLicenseImage();
        String contentType = MimeSniffer.guessImageContentType(bytes);
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
    // 라이선스 정보 조회 (프론트 모달 정보용)
    // ─────────────────────────────────────────────────────────────────────────────
    @GetMapping("/{userid}/license/info")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getLicenseInfo(@PathVariable String userid) {
        var u = userRepository.findByUserid(userid).orElse(null);
        if (u == null)
            return notFound();

        var dlOpt = driverLicenseRepository.findByUser_UserNum(u.getUserNum());
        if (dlOpt.isEmpty())
            return notFound();

        var dl = dlOpt.get();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("holderName", dl.getHolderName());
        body.put("birthDate", dl.getBirthDate());
        body.put("licenseNumber", dl.getLicenseNumber());
        body.put("acquiredDate", dl.getAcquiredDate());
        body.put("hasImage", dl.getLicenseImage() != null && dl.getLicenseImage().length > 0);
        return ResponseEntity.ok(body);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 승인 (PENDING → APPROVED) — 면허 이미지가 실제로 있어야 승인 + 승인 메일
    // ─────────────────────────────────────────────────────────────────────────────
    @PostMapping("/{userid}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> approve(@PathVariable String userid) {
        var u = userRepository.findByUserid(userid).orElse(null);
        if (u == null)
            return notFound();

        if (u.getRole() != Role.ROLE_DRIVER) {
            return badRequest("NOT_A_DRIVER");
        }
        if (u.getApprovalStatus() != ApprovalStatus.PENDING) {
            return conflict("INVALID_STATUS", Map.of("current", u.getApprovalStatus().name()));
        }

        var dlOpt = driverLicenseRepository.findByUser_UserNum(u.getUserNum());
        if (dlOpt.isEmpty() || dlOpt.get().getLicenseImage() == null || dlOpt.get().getLicenseImage().length == 0) {
            return conflict("LICENSE_REQUIRED", Map.of(
                    "message", "승인을 위해 운전면허 이미지가 등록되어 있어야 합니다."));
        }

        u.setApprovalStatus(ApprovalStatus.APPROVED);
        userRepository.save(u);

        sendApprovalMailAfterCommit(u);

        return ok(Map.of("ok", true, "status", "APPROVED"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 거절 (PENDING → REJECTED) + optional 사유 + 거절 메일
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
        if (u == null)
            return notFound();

        if (u.getRole() != Role.ROLE_DRIVER) {
            return badRequest("NOT_A_DRIVER");
        }
        if (u.getApprovalStatus() != ApprovalStatus.PENDING) {
            return conflict("INVALID_STATUS", Map.of("current", u.getApprovalStatus().name()));
        }

        u.setApprovalStatus(ApprovalStatus.REJECTED);
        userRepository.save(u);

        String reason = (body != null && StringUtils.hasText(body.getReason())) ? body.getReason().trim() : null;

        sendRejectionMailAfterCommit(u, reason);

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("ok", true);
        resp.put("status", "REJECTED");
        if (reason != null) {
            resp.put("reason", reason);
        }
        return ok(resp);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 내부: 메일 전송 (트랜잭션 커밋 후)
    // ─────────────────────────────────────────────────────────────────────────────
    private void sendApprovalMailAfterCommit(UserEntity u) {
        final String to = safeEmail(u.getEmail());
        if (to == null)
            return;

        final String when = LocalDateTime.now(KST).format(TS_FMT);
        final String subject = "[HopOn] 기사 회원 승인 완료: " + nonNull(u.getUserid());

        final String html = """
                <p>%s님, 안녕하세요.</p>
                <p>요청하신 기사 회원 등록이 <b style="color:#2bb673">승인</b>되었습니다.</p>
                <ul>
                  <li>아이디: <b>%s</b></li>
                  <li>승인일시: %s (KST)</li>
                </ul>
                <p>이제 기사 앱에서 로그인 후 운행을 시작할 수 있습니다.</p>
                <p style="color:#666;font-size:12px">※ 본 메일은 발신 전용입니다.</p>
                """.formatted(esc(u.getUsername()), esc(u.getUserid()), esc(when));

        final String text = """
                %s님, 안녕하세요.
                요청하신 기사 회원 등록이 승인되었습니다.

                아이디: %s
                승인일시: %s (KST)

                이제 기사 앱에서 로그인 후 운행을 시작할 수 있습니다.
                """.formatted(nonNull(u.getUsername()), nonNull(u.getUserid()), when);

        sendMailAfterCommit(to, subject, html, text);
    }

    private void sendRejectionMailAfterCommit(UserEntity u, String reason) {
        final String to = safeEmail(u.getEmail());
        if (to == null)
            return;

        final String when = LocalDateTime.now(KST).format(TS_FMT);
        final String subject = "[HopOn] 기사 회원 승인 거절 안내: " + nonNull(u.getUserid());
        final String reasonText = StringUtils.hasText(reason) ? reason.trim() : "요건 미충족";

        final String html = """
                <p>%s님, 안녕하세요.</p>
                <p>기사 회원 등록 요청이 <b style="color:#e74c3c">거절</b>되었습니다.</p>
                <ul>
                  <li>아이디: <b>%s</b></li>
                  <li>처리일시: %s (KST)</li>
                  <li>사유: %s</li>
                </ul>
                <p>필요 서류 또는 이미지(운전면허) 상태를 확인하시고 문의를 통해 다시 보내주시기 바랍니다.</p>
                <p style="color:#666;font-size:12px">※ 본 메일은 발신 전용입니다.</p>
                """.formatted(esc(u.getUsername()), esc(u.getUserid()), esc(when), esc(reasonText));

        final String text = """
                %s님, 안녕하세요.
                기사 회원 등록 요청이 거절되었습니다.

                아이디: %s
                처리일시: %s (KST)
                사유: %s

                필요 서류 또는 이미지를 보완 후 문의를 통해 다시 보내주시기 바랍니다.
                """.formatted(nonNull(u.getUsername()), nonNull(u.getUserid()), when, reasonText);

        sendMailAfterCommit(to, subject, html, text);
    }

    /** 트랜잭션 커밋 후 메일 발송 */
    private void sendMailAfterCommit(String to, String subject, String htmlBody, String textBody) {
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    MimeMessage msg = mailSender.createMimeMessage();
                    // multipart=true (대안 텍스트/인라인 가능)
                    MimeMessageHelper helper = new MimeMessageHelper(msg, true, "UTF-8");
                    helper.setFrom(new InternetAddress(fromAddress, fromName, "UTF-8"));
                    helper.setTo(to);
                    helper.setSubject(subject);

                    if (htmlBody != null && textBody != null) {
                        helper.setText(textBody, htmlBody);
                    } else if (htmlBody != null) {
                        helper.setText(htmlBody, true);
                    } else {
                        helper.setText(textBody != null ? textBody : " ");
                    }
                    mailSender.send(msg);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private static String nonNull(String s) {
        return s == null ? "" : s;
    }

    private static String esc(String s) {
        return HtmlUtils.htmlEscape(nonNull(s));
    }

    private static String safeEmail(String email) {
        if (!StringUtils.hasText(email))
            return null;
        String e = email.trim();
        return e.contains("@") ? e : null;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 내부: 매핑/유틸
    // ─────────────────────────────────────────────────────────────────────────────
    // DriverAdminController.java 내 매핑 유틸
    private UserResponse toResponse(UserEntity u) {
        boolean hasDl = driverLicenseRepository.existsByUser_UserNum(u.getUserNum());
        boolean hasImg = u.getProfileImage() != null && u.getProfileImage().length > 0;

        String roleLabel = switch (u.getRole()) {
            case ROLE_ADMIN -> "관리자";
            case ROLE_DRIVER -> "기사";
            case ROLE_USER -> "사용자";
        };

        return UserResponse.builder()
                .userNum(u.getUserNum())
                .userid(u.getUserid())
                .username(u.getUsername())
                .email(u.getEmail())
                .tel(u.getTel())
                .role(u.getRole())
                .roleLabel(roleLabel)
                .hasProfileImage(hasImg)
                .company(u.getCompany())
                .approvalStatus(u.getApprovalStatus())
                .hasDriverLicenseFile(hasDl)
                .createdAtIso(UserResponse.toIsoOrNull(u.getCreatedAt()))
                .lastLoginAtIso(UserResponse.toIsoOrNull(u.getLastLoginAt()))
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
        if (extra != null)
            body.putAll(extra);
        return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
    }
}

/** 간단 MIME 스니퍼 */
final class MimeSniffer {
    private MimeSniffer() {
    }

    static String guessImageContentType(byte[] b) {
        if (b == null || b.length < 4)
            return MediaType.APPLICATION_OCTET_STREAM_VALUE;
        if ((b[0] & 0xFF) == 0xFF && (b[1] & 0xFF) == 0xD8 && (b[2] & 0xFF) == 0xFF)
            return MediaType.IMAGE_JPEG_VALUE; // JPEG
        if ((b[0] & 0xFF) == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47)
            return MediaType.IMAGE_PNG_VALUE; // PNG
        if (b[0] == 0x47 && b[1] == 0x49 && b[2] == 0x46 && b[3] == 0x38)
            return MediaType.IMAGE_GIF_VALUE; // GIF
        return MediaType.APPLICATION_OCTET_STREAM_VALUE;
    }

    static String extFor(String ct) {
        if (MediaType.IMAGE_JPEG_VALUE.equals(ct))
            return ".jpg";
        if (MediaType.IMAGE_PNG_VALUE.equals(ct))
            return ".png";
        if (MediaType.IMAGE_GIF_VALUE.equals(ct))
            return ".gif";
        return ".bin";
    }
}
