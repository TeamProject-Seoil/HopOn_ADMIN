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
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/admin/drivers")
@RequiredArgsConstructor
public class DriverAdminController {

    private final UserRepository userRepository;
    private final DriverLicenseRepository driverLicenseRepository;

    // 메일 발송
    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromAddress;

    @Value("${app.mail.from-name:HopOn Admin}")
    private String fromName;

    private static final ZoneId KST = ZoneId.of("Asia/Seoul");
    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    /* ------------------------------------------------------------------------
     * 공통: 페이지 기본 정렬(createdAt ASC) 보정
     * ------------------------------------------------------------------------ */
    private Pageable defaultPageable(Pageable pageable) {
        if (pageable == null) {
            return PageRequest.of(0, 20, Sort.by(Sort.Order.asc("createdAt")));
        }
        if (pageable.getSort().isUnsorted()) {
            return PageRequest.of(
                    Math.max(0, pageable.getPageNumber()),
                    Math.max(1, pageable.getPageSize()),
                    Sort.by(Sort.Order.asc("createdAt"))
            );
        }
        return pageable;
    }

    /* ------------------------------------------------------------------------
     * 승인 대기 목록
     * GET /admin/drivers/pending?page=0&size=10&sort=createdAt,asc&search=kim
     * ------------------------------------------------------------------------ */
    @GetMapping("/pending")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserResponse>> listPending(
            @RequestParam(value = "search", required = false) String search,
            Pageable pageable) {

        Pageable pg = defaultPageable(pageable);
        String q = StringUtils.hasText(search) ? search.trim() : null;

        Page<UserEntity> pageData = userRepository.searchByRoleAndStatus(
                Role.ROLE_DRIVER, ApprovalStatus.PENDING, q, pg
        );
        return ResponseEntity.ok(pageData.map(this::toResponse));
    }

    /* ------------------------------------------------------------------------
     * 승인됨 목록
     * ------------------------------------------------------------------------ */
    @GetMapping("/approved")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserResponse>> listApproved(
            @RequestParam(value = "search", required = false) String search,
            Pageable pageable) {

        Pageable pg = defaultPageable(pageable);
        String q = StringUtils.hasText(search) ? search.trim() : null;

        Page<UserEntity> pageData = userRepository.searchByRoleAndStatus(
                Role.ROLE_DRIVER, ApprovalStatus.APPROVED, q, pg
        );
        return ResponseEntity.ok(pageData.map(this::toResponse));
    }

    /* ------------------------------------------------------------------------
     * 승인 거절 목록
     * ------------------------------------------------------------------------ */
    @GetMapping("/rejected")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserResponse>> listRejected(
            @RequestParam(value = "search", required = false) String search,
            Pageable pageable) {

        Pageable pg = defaultPageable(pageable);
        String q = StringUtils.hasText(search) ? search.trim() : null;

        Page<UserEntity> pageData = userRepository.searchByRoleAndStatus(
                Role.ROLE_DRIVER, ApprovalStatus.REJECTED, q, pg
        );
        return ResponseEntity.ok(pageData.map(this::toResponse));
    }

    /* ------------------------------------------------------------------------
     * 탭 카운트
     * ------------------------------------------------------------------------ */
    @GetMapping("/counts")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> counts() {
        long approved = userRepository.countByRoleAndApprovalStatus(Role.ROLE_DRIVER, ApprovalStatus.APPROVED);
        long rejected = userRepository.countByRoleAndApprovalStatus(Role.ROLE_DRIVER, ApprovalStatus.REJECTED);
        long pending  = userRepository.countByRoleAndApprovalStatus(Role.ROLE_DRIVER, ApprovalStatus.PENDING);
        return ResponseEntity.ok(Map.of(
                "approved", approved,
                "rejected", rejected,
                "pending",  pending
        ));
    }

    /* ------------------------------------------------------------------------
     * 프로필 이미지 (원래 경로) : /admin/drivers/{userid}/profile
     * ------------------------------------------------------------------------ */
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

    /* ------------------------------------------------------------------------
     * 라이선스 이미지 조회 (inline)
     * ------------------------------------------------------------------------ */
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

    /* ------------------------------------------------------------------------
     * 라이선스 정보 조회 (모달용)
     * ------------------------------------------------------------------------ */
    @GetMapping("/{userid}/license/info")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getLicenseInfo(@PathVariable String userid) {
        var u = userRepository.findByUserid(userid).orElse(null);
        if (u == null) return notFound();

        var dlOpt = driverLicenseRepository.findByUser_UserNum(u.getUserNum());
        if (dlOpt.isEmpty()) return notFound();

        var dl = dlOpt.get();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("holderName", dl.getHolderName());
        body.put("birthDate", dl.getBirthDate());
        body.put("licenseNumber", dl.getLicenseNumber());
        body.put("acquiredDate", dl.getAcquiredDate());
        body.put("hasImage", dl.getLicenseImage() != null && dl.getLicenseImage().length > 0);
        return ResponseEntity.ok(body);
    }

    /* ------------------------------------------------------------------------
     * 상태 일괄 변경 API
     *  - 어떤 현재 상태든 목표 상태로 변경
     *  - APPROVED 로 변경 시 운전면허 이미지 필수
     *  - APPROVED/REJECTED 변경 시 각각 승인/거절 메일 발송
     *  - PENDING 으로 변경 시 메일 미발송
     * ------------------------------------------------------------------------ */
    @Data
    public static class StatusChangeRequest {
        private ApprovalStatus status;
        private String reason; // REJECTED 시 옵션
    }

    @PostMapping("/{userid}/status")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> changeStatus(@PathVariable String userid,
                                          @RequestBody StatusChangeRequest req) {
        if (req == null || req.getStatus() == null) {
            return badRequest("STATUS_REQUIRED");
        }
        var target = req.getStatus();

        var u = userRepository.findByUserid(userid).orElse(null);
        if (u == null) return notFound();

        if (u.getRole() != Role.ROLE_DRIVER) {
            return badRequest("NOT_A_DRIVER");
        }

        // 이미 동일 상태면 OK 반환(멱등)
        if (u.getApprovalStatus() == target) {
            return ok(Map.of("ok", true, "status", target.name()));
        }

        // APPROVED 로 변경 시 면허 이미지 필수
        if (target == ApprovalStatus.APPROVED) {
            var dlOpt = driverLicenseRepository.findByUser_UserNum(u.getUserNum());
            if (dlOpt.isEmpty() || dlOpt.get().getLicenseImage() == null || dlOpt.get().getLicenseImage().length == 0) {
                return conflict("LICENSE_REQUIRED", Map.of(
                        "message", "승인을 위해 운전면허 이미지가 등록되어 있어야 합니다."));
            }
        }

        // 상태 변경
        u.setApprovalStatus(target);
        userRepository.save(u);

        // 메일 발송
        if (target == ApprovalStatus.APPROVED) {
    sendApprovalMailAfterCommit(u);
} else if (target == ApprovalStatus.REJECTED) {
    String reason = StringUtils.hasText(req.getReason()) ? req.getReason().trim() : null;
    sendRejectionMailAfterCommit(u, reason);
} else if (target == ApprovalStatus.PENDING) {
    // ✅ 대기 전환 시에도 메일 알림
    sendPendingMailAfterCommit(u);
}

        return ok(Map.of("ok", true, "status", target.name()));
    }

    /* ------------------------------------------------------------------------
     * 기존 approve/reject (호환) — 내부적으로 changeStatus 사용
     * ------------------------------------------------------------------------ */
    @PostMapping("/{userid}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> approveCompat(@PathVariable String userid) {
        StatusChangeRequest r = new StatusChangeRequest();
        r.setStatus(ApprovalStatus.APPROVED);
        return changeStatus(userid, r);
    }

    @Data
    public static class RejectRequest { private String reason; }

    @PostMapping("/{userid}/reject")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> rejectCompat(@PathVariable String userid,
                                          @RequestBody(required = false) RejectRequest body) {
        StatusChangeRequest r = new StatusChangeRequest();
        r.setStatus(ApprovalStatus.REJECTED);
        r.setReason(body != null ? body.getReason() : null);
        return changeStatus(userid, r);
    }

    /* ------------------------------------------------------------------------
     * 메일 전송 (트랜잭션 커밋 후)
     * ------------------------------------------------------------------------ */
    private void sendApprovalMailAfterCommit(UserEntity u) {
        final String to = safeEmail(u.getEmail());
        if (to == null) return;

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


    private void sendPendingMailAfterCommit(UserEntity u) {
    final String to = safeEmail(u.getEmail());
    if (to == null) return;

    final String when = LocalDateTime.now(KST).format(TS_FMT);
    final String subject = "[HopOn] 기사 회원 상태 변경: 승인대기 - " + nonNull(u.getUserid());

    final String html = """
            <p>%s님, 안녕하세요.</p>
            <p>기사 회원 상태가 <b style="color:#f59e0b">승인대기</b>로 변경되었습니다.</p>
            <ul>
              <li>아이디: <b>%s</b></li>
              <li>처리일시: %s (KST)</li>
            </ul>
            <p>관리자 검토가 완료되면 별도 안내 메일을 드리겠습니다.</p>
            <p style="color:#666;font-size:12px">※ 본 메일은 발신 전용입니다.</p>
            """.formatted(esc(u.getUsername()), esc(u.getUserid()), esc(when));

    final String text = """
            %s님, 안녕하세요.
            기사 회원 상태가 승인대기로 변경되었습니다.

            아이디: %s
            처리일시: %s (KST)

            관리자 검토가 완료되면 안내 드리겠습니다.
            """.formatted(nonNull(u.getUsername()), nonNull(u.getUserid()), when);

    sendMailAfterCommit(to, subject, html, text);
}


    private void sendRejectionMailAfterCommit(UserEntity u, String reason) {
        final String to = safeEmail(u.getEmail());
        if (to == null) return;

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
            @Override public void afterCommit() {
                try {
                    MimeMessage msg = mailSender.createMimeMessage();
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

    /* ------------------------------------------------------------------------
     * 매핑/유틸
     * ------------------------------------------------------------------------ */
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

    private static String nonNull(String s) {
        return s == null ? "" : s;
    }

    private static String esc(String s) {
        return HtmlUtils.htmlEscape(nonNull(s));
    }

    private static String safeEmail(String email) {
        if (!StringUtils.hasText(email)) return null;
        String e = email.trim();
        return e.contains("@") ? e : null;
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

/** 간단 MIME 스니퍼 */
final class MimeSniffer {
    private MimeSniffer() {}

    static String guessImageContentType(byte[] b) {
        if (b == null || b.length < 4)
            return MediaType.APPLICATION_OCTET_STREAM_VALUE;
        if ((b[0] & 0xFF) == 0xFF && (b[1] & 0xFF) == 0xD8 && (b[2] & 0xFF) == 0xFF)
            return MediaType.IMAGE_JPEG_VALUE; // JPEG
        if ((b[0] & 0xFF) == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47)
            return MediaType.IMAGE_PNG_VALUE;  // PNG
        if (b[0] == 0x47 && b[1] == 0x49 && b[2] == 0x46 && b[3] == 0x38)
            return MediaType.IMAGE_GIF_VALUE;  // GIF
        return MediaType.APPLICATION_OCTET_STREAM_VALUE;
    }

    static String extFor(String ct) {
        if (MediaType.IMAGE_JPEG_VALUE.equals(ct)) return ".jpg";
        if (MediaType.IMAGE_PNG_VALUE.equals(ct))  return ".png";
        if (MediaType.IMAGE_GIF_VALUE.equals(ct))  return ".gif";
        return ".bin";
    }
}
