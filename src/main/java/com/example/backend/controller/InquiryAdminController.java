// src/main/java/com/example/backend/controller/InquiryAdminController.java
package com.example.backend.controller;

import com.example.backend.dto.InquiryDtos;
import com.example.backend.entity.*;
import com.example.backend.repository.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/admin/inquiries")
@RequiredArgsConstructor
public class InquiryAdminController {

    private final InquiryRepository inquiryRepository;
    private final InquiryAttachmentRepository attachmentRepository;
    private final InquiryReplyRepository replyRepository;

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}") private String fromAddress;
    @Value("${app.mail.from-name:HopOn Support}") private String fromName;

    private Pageable defaultPageable(Pageable pageable) {
        if (pageable == null || pageable.isUnpaged()) {
            return PageRequest.of(0, 20, Sort.by(Sort.Order.desc("createdAt")));
        }
        if (pageable.getSort().isUnsorted()) {
            return PageRequest.of(pageable.getPageNumber(), pageable.getPageSize(),
                    Sort.by(Sort.Order.desc("createdAt")));
        }
        return pageable;
    }

    /* 목록 */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<InquiryDtos.InquiryListItem>> list(
            @RequestParam(value = "status", required = false) InquiryStatus status,
            @RequestParam(value = "q", required = false) String q,
            Pageable pageable
    ){
        Pageable pg = defaultPageable(pageable);
        Page<InquiryEntity> data = inquiryRepository.search(status, StringUtils.hasText(q) ? q.trim() : null, pg);
        return ResponseEntity.ok(data.map(InquiryDtos::toListItem));
    }

    /* 상세 */
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> detail(@PathVariable Long id){
        var inq = inquiryRepository.findById(id).orElse(null);
        if (inq == null) return notFound();
        inq.getAttachments().size(); // ensure load
        inq.getReplies().size();
        return ResponseEntity.ok(InquiryDtos.toDetail(inq));
    }

    /* 첨부 다운로드/인라인 */
    @GetMapping("/{id}/attachments/{attId}")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<byte[]> download(@PathVariable Long id, @PathVariable Long attId,
                                       @RequestParam(value = "inline", defaultValue = "true") boolean inline) {
    var inq = inquiryRepository.findById(id).orElse(null);
    if (inq == null) return notFound();
    var att = attachmentRepository.findById(attId).orElse(null);
    if (att == null || att.getInquiry() == null || !att.getInquiry().getId().equals(inq.getId())) {
        return notFound();
    }

    HttpHeaders h = new HttpHeaders();
    h.setContentType(MediaType.parseMediaType(att.getContentType()));
    h.setContentLength(att.getSize());
    ContentDisposition cd = (inline ? ContentDisposition.inline() : ContentDisposition.attachment())
            .filename(URLEncoder.encode(att.getFilename(), StandardCharsets.UTF_8).replace("+", "%20"))
            .build();
    h.setContentDisposition(cd);

    return new ResponseEntity<>(att.getBytes(), h, HttpStatus.OK);
}

    /* 상태 변경 */
    @PutMapping("/{id}/status")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> changeStatus(@PathVariable Long id,
                                          @RequestParam InquiryStatus status){
        var inq = inquiryRepository.findById(id).orElse(null);
        if (inq == null) return notFound();
        inq.setStatus(status);
        inquiryRepository.save(inq);
        return ok(java.util.Map.of("ok", true, "status", status.name()));
    }

    @Data
    public static class ReplyRequest {
        private String message;
    }

    /* 답변 등록 + 메일 발송 */
    @PostMapping("/{id}/reply")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> reply(@PathVariable Long id, @RequestBody ReplyRequest req) {
        if (req == null || !StringUtils.hasText(req.getMessage()))
            return bad("MESSAGE_REQUIRED");

        var inq = inquiryRepository.findById(id).orElse(null);
        if (inq == null) return notFound();

        // 저장
        InquiryReplyEntity r = InquiryReplyEntity.builder()
                .inquiry(inq)
                .message(req.getMessage().trim())
                .build();
        replyRepository.save(r);

        // 상태 갱신
        inq.setStatus(InquiryStatus.ANSWERED);
        inquiryRepository.save(inq);

        // 메일 발송(트랜잭션 커밋 후)
        final String to = safeEmail(inq.getEmail());
        if (to != null) {
            String subject = "[HopOn] 문의에 대한 답변: " + nonNull(inq.getTitle());
            String html = """
                    <p>%s님, 안녕하세요.</p>
                    <p>접수하신 문의에 대한 답변입니다.</p>
                    <hr/>
                    <p style="white-space:pre-wrap">%s</p>
                    <hr/>
                    <p style="color:#666;font-size:12px">※ 본 메일은 발신 전용입니다.</p>
                    """.formatted(esc(inq.getName()), esc(req.getMessage()));
            String text = """
                    %s님, 안녕하세요.
                    접수하신 문의에 대한 답변입니다.

                    --------------------
                    %s
                    --------------------
                    (본 메일은 발신 전용)
                    """.formatted(nonNull(inq.getName()), req.getMessage());
            sendMailAfterCommit(to, subject, html, text);
        }

        return ok(java.util.Map.of("ok", true));
    }

    /* 공통 유틸/응답 */
    private static <T> ResponseEntity<T> notFound() {
    return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
}
    private static ResponseEntity<?> ok(Object body){ return ResponseEntity.ok(body); }
    private static ResponseEntity<?> bad(String reason){ return ResponseEntity.badRequest().body(java.util.Map.of("ok", false, "reason", reason)); }

    private static String esc(String s){ return org.springframework.web.util.HtmlUtils.htmlEscape(nonNull(s)); }
    private static String nonNull(String s){ return s == null ? "" : s; }
    private static String safeEmail(String email){
        if (!StringUtils.hasText(email)) return null;
        String e = email.trim();
        return e.contains("@") ? e : null;
    }

    private void sendMailAfterCommit(String to, String subject, String htmlBody, String textBody) {
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override public void afterCommit() {
                try {
                    MimeMessage msg = mailSender.createMimeMessage();
                    MimeMessageHelper helper = new MimeMessageHelper(msg, true, "UTF-8");
                    helper.setFrom(new InternetAddress(fromAddress, fromName, "UTF-8"));
                    helper.setTo(to);
                    helper.setSubject(subject);
                    helper.setText(textBody, htmlBody);
                    mailSender.send(msg);
                } catch (Exception e) { e.printStackTrace(); }
            }
        });
    }
}
