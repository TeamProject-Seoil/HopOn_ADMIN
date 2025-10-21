// src/main/java/com/example/backend/controller/UserMediaController.java
package com.example.backend.controller;

import com.example.backend.entity.UserEntity;
import com.example.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.util.DigestUtils;
import org.springframework.web.bind.annotation.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

@RestController
@RequestMapping("/admin/users")
@RequiredArgsConstructor
public class UserMediaController {

    private final UserRepository userRepository;

    @GetMapping("/{userid}/profile-image")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<byte[]> getProfileImage(@PathVariable String userid,
            @RequestHeader(value = "If-None-Match", required = false) String inm) {
        Optional<UserEntity> opt = userRepository.findByUserid(userid);
        if (opt.isEmpty())
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();

        byte[] bytes = opt.get().getProfileImage();
        if (bytes == null || bytes.length == 0) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        String contentType = guess(bytes); // 간단 MIME 추론 (아래 메서드)
        String etag = "\"" + DigestUtils.md5DigestAsHex(bytes) + "\"";
        if (etag.equals(inm)) {
            return ResponseEntity.status(HttpStatus.NOT_MODIFIED)
                    .eTag(etag)
                    .build();
        }

        String filename = URLEncoder.encode("profile-" + userid + extFor(contentType), StandardCharsets.UTF_8)
                .replace("+", "%20");
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .contentLength(bytes.length)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.inline().filename(filename).build().toString())
                .cacheControl(CacheControl.maxAge(java.time.Duration.ofDays(7)).cachePublic())
                .eTag(etag)
                .body(bytes);
    }

    // ── 아주 단순한 스니퍼 ─────────────────────────────────────────────
    private static String guess(byte[] b) {
        if (b.length >= 3 && (b[0] & 0xFF) == 0xFF && (b[1] & 0xFF) == 0xD8 && (b[2] & 0xFF) == 0xFF)
            return MediaType.IMAGE_JPEG_VALUE;
        if (b.length >= 4 && (b[0] & 0xFF) == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47)
            return MediaType.IMAGE_PNG_VALUE;
        if (b.length >= 4 && b[0] == 0x47 && b[1] == 0x49 && b[2] == 0x46 && b[3] == 0x38)
            return MediaType.IMAGE_GIF_VALUE;
        return MediaType.APPLICATION_OCTET_STREAM_VALUE;
    }

    private static String extFor(String ct) {
        if (MediaType.IMAGE_JPEG_VALUE.equals(ct))
            return ".jpg";
        if (MediaType.IMAGE_PNG_VALUE.equals(ct))
            return ".png";
        if (MediaType.IMAGE_GIF_VALUE.equals(ct))
            return ".gif";
        return ".bin";
    }
}
