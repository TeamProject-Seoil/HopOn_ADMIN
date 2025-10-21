// src/main/java/com/example/backend/dto/InquiryDtos.java
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

    @Getter @Setter @Builder
    public static class AttachmentMeta {
        private Long id;
        private String filename;
        private String contentType;
        private long size;
    }

    @Getter @Setter @Builder
    public static class ReplyInfo {
        private Long id;
        private String message;
        private Long adminUserNum;
        private String createdAt;
    }

    @Getter @Setter @Builder
    public static class InquiryListItem {
        private Long id;
        private String title;
        private String name;
        private String userid;
        private String email;
        private InquiryStatus status;
        private String createdAt;
        private String updatedAt;
    }

    @Getter @Setter @Builder
    public static class InquiryDetail {
        private Long id;
        private String title;
        private String content;
        private String name;
        private String userid;
        private String email;
        private InquiryStatus status;
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
                .createdAt(toIso(e.getCreatedAt()))
                .updatedAt(toIso(e.getUpdatedAt()))
                .attachments(e.getAttachments().stream().map(InquiryDtos::toMeta).toList())
                .replies(e.getReplies().stream().map(InquiryDtos::toReply).toList())
                .build();
    }

    private static AttachmentMeta toMeta(InquiryAttachmentEntity a){
        return AttachmentMeta.builder()
                .id(a.getId())
                .filename(a.getFilename())
                .contentType(a.getContentType())
                .size(a.getSize())
                .build();
    }
    private static ReplyInfo toReply(InquiryReplyEntity r){
        return ReplyInfo.builder()
                .id(r.getId())
                .message(r.getMessage())
                .adminUserNum(r.getAdminUserNum())
                .createdAt(toIso(r.getCreatedAt()))
                .build();
    }

    private static String toIso(java.time.LocalDateTime t){
        if (t == null) return null;
        return OffsetDateTime.of(t, ZoneOffset.UTC).toString();
    }
}
