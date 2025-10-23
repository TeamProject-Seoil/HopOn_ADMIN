package com.example.backend.dto;

import com.example.backend.entity.InquiryEntity;
import com.example.backend.entity.InquiryAttachmentEntity;
import com.example.backend.entity.InquiryReplyEntity;
import com.example.backend.entity.InquiryStatus;
import lombok.*;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

public class InquiryDtos {

    @Getter
    @Setter
    @Builder
    public static class AttachmentMeta {
        private Long id;
        private String filename;
        private String contentType;
        private long size;
    }

    @Getter
    @Setter
    @Builder
    public static class ReplyInfo {
        private Long id;
        private String message;
        private Long adminUserNum;
        private String createdAt;
    }

    @Getter
    @Setter
    @Builder
    public static class InquiryListItem {
        private Long id;
        private String title;
        private String name;
        private String userid;
        private String email;
        private InquiryStatus status;
        private String createdAt;
        private String updatedAt;
        // 목록에 굳이 비밀글 여부가 필요 없으면 제외해도 되지만, 필요하면 주석 해제
        // private boolean isSecret;
    }

    @Getter
    @Setter
    @Builder
    public static class InquiryDetail {
        private Long id;
        private String title;
        private String content;
        private String name;
        private String userid;
        private String email;
        private InquiryStatus status;
        private boolean isSecret; // ✅ 상세에서 비밀글 여부 확인 가능
        private String createdAt;
        private String updatedAt;
        private List<AttachmentMeta> attachments;
        private List<ReplyInfo> replies;
    }

    public static InquiryListItem toListItem(InquiryEntity e) {
        return InquiryListItem.builder()
                .id(e.getId())
                .title(e.getTitle())
                .name(e.getName())
                .userid(e.getUserid())
                .email(e.getEmail())
                .status(e.getStatus())
                .createdAt(toIso(e.getCreatedAt()))
                .updatedAt(toIso(e.getUpdatedAt()))
                // .isSecret(e.isSecret())
                .build();
    }

    public static InquiryDetail toDetail(InquiryEntity e) {
        return InquiryDetail.builder()
                .id(e.getId())
                .title(e.getTitle())
                .content(e.getContent())
                .name(e.getName())
                .userid(e.getUserid())
                .email(e.getEmail())
                .status(e.getStatus())
                .isSecret(e.isSecret())
                .createdAt(toIso(e.getCreatedAt()))
                .updatedAt(toIso(e.getUpdatedAt()))
                .attachments(e.getAttachments().stream().map(InquiryDtos::toMeta).toList())
                .replies(e.getReplies().stream().map(InquiryDtos::toReply).toList())
                .build();
    }

    private static AttachmentMeta toMeta(InquiryAttachmentEntity a) {
        return AttachmentMeta.builder()
                .id(a.getId())
                .filename(a.getFilename())
                .contentType(a.getContentType())
                .size(a.getSize())
                .build();
    }

    private static ReplyInfo toReply(InquiryReplyEntity r) {
        return ReplyInfo.builder()
                .id(r.getId())
                .message(r.getMessage())
                .adminUserNum(r.getAdminUserNum())
                .createdAt(toIso(r.getCreatedAt()))
                .build();
    }

    private static String toIso(java.time.LocalDateTime t) {
        if (t == null)
            return null;
        // DB는 timezone 미포함 → UTC 기준 ISO 문자열로 직렬화(기존 로직 유지)
        return OffsetDateTime.of(t, ZoneOffset.UTC).toString();
    }
}
