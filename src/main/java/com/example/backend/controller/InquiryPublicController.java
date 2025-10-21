// src/main/java/com/example/backend/controller/InquiryPublicController.java
package com.example.backend.controller;

import com.example.backend.entity.*;
import com.example.backend.repository.*;
import lombok.*;
import org.springframework.http.*;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/inquiries")
@RequiredArgsConstructor
public class InquiryPublicController {

    private final InquiryRepository inquiryRepository;
    private final InquiryAttachmentRepository attachmentRepository;

    @Data
    public static class SubmitRequest {
        private String name;
        private String userid; // 로그인 시 전달(미로그인 null)
        private boolean anonymous; // true면 name은 "익명" 처리
        private String email;
        private String title;
        private String content;
    }

    /** 문의 접수 (multipart: files[] 이미지 다중 업로드) */
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> submit(
            @RequestPart("data") SubmitRequest req,
            @RequestPart(name = "files", required = false) List<MultipartFile> files
    ) {
        if (req == null ||
            !StringUtils.hasText(req.getEmail()) ||
            !StringUtils.hasText(req.getTitle()) ||
            !StringUtils.hasText(req.getContent())) {
            return ResponseEntity.badRequest().body(msg("INVALID", "email/title/content 필수"));
        }

        String name = (req.isAnonymous() ? "익명" : (StringUtils.hasText(req.getName()) ? req.getName().trim() : "익명"));
        InquiryEntity inq = InquiryEntity.builder()
                .name(name)
                .userid(StringUtils.hasText(req.getUserid()) ? req.getUserid().trim() : null)
                .email(req.getEmail().trim())
                .title(req.getTitle().trim())
                .content(req.getContent().trim())
                .status(InquiryStatus.OPEN)
                .build();
        inquiryRepository.save(inq);

        // 첨부(이미지만 허용)
        if (files != null) {
            for (MultipartFile f : files) {
                if (f == null || f.isEmpty()) continue;
                String ct = f.getContentType() == null ? "application/octet-stream" : f.getContentType();
                if (!(ct.startsWith("image/jpeg") || ct.startsWith("image/png") || ct.startsWith("image/gif")))
                    continue; // 이미지만
                try {
                    InquiryAttachmentEntity a = InquiryAttachmentEntity.builder()
                            .inquiry(inq)
                            .filename(f.getOriginalFilename() == null ? "file" : f.getOriginalFilename())
                            .contentType(ct)
                            .bytes(f.getBytes())
                            .size(f.getSize())
                            .build();
                    attachmentRepository.save(a);
                } catch (Exception ignore) {}
            }
        }
        return ResponseEntity.ok(msg("ok", inq.getId()));
    }

    private static java.util.Map<String,Object> msg(String k, Object v){
        return java.util.Map.of(k, v);
    }
}
