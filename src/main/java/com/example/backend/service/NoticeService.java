// src/main/java/com/example/backend/service/NoticeService.java
package com.example.backend.service;

import com.example.backend.dto.*;
import com.example.backend.entity.*;
import com.example.backend.repository.NoticeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
public class NoticeService {

    private final NoticeRepository repository;

    private Pageable defaultPage(Pageable pageable) {
        if (pageable == null || pageable.isUnpaged()) {
            return PageRequest.of(0, 20, Sort.by(Sort.Order.desc("updatedAt")));
        }
        if (pageable.getSort().isUnsorted()) {
            return PageRequest.of(pageable.getPageNumber(), pageable.getPageSize(),
                    Sort.by(Sort.Order.desc("updatedAt")));
        }
        return pageable;
    }

    public Page<NoticeResponse> search(String q, NoticeTarget target, NoticeType type, Pageable pageable) {
        String query = StringUtils.hasText(q) ? q.trim() : null;
        var page = repository.search(query, target, type, defaultPage(pageable));
        return page.map(this::toDto);
    }

    public NoticeResponse get(Long id) {
        return repository.findById(id).map(this::toDto)
                .orElseThrow(() -> new IllegalArgumentException("NOTICE_NOT_FOUND"));
    }

    @Transactional
    public NoticeResponse create(NoticeRequest req) {
        var n = NoticeEntity.builder()
                .title(req.title())
                .content(req.content())
                .noticeType(req.noticeType())
                .targetRole(req.targetRole())
                .viewCount(0L)
                .build();
        return toDto(repository.save(n));
    }

    @Transactional
    public NoticeResponse update(Long id, NoticeRequest req) {
        var n = repository.findById(id).orElseThrow(() -> new IllegalArgumentException("NOTICE_NOT_FOUND"));
        n.setTitle(req.title());
        n.setContent(req.content());
        n.setNoticeType(req.noticeType());
        n.setTargetRole(req.targetRole());
        return toDto(n);
    }

    @Transactional
    public void delete(Long id) {
        if (!repository.existsById(id)) throw new IllegalArgumentException("NOTICE_NOT_FOUND");
        repository.deleteById(id);
    }

    private NoticeResponse toDto(NoticeEntity n) {
        return new NoticeResponse(
                n.getId(), n.getTitle(), n.getContent(),
                n.getNoticeType(), n.getTargetRole(),
                n.getViewCount(), n.getCreatedAt(), n.getUpdatedAt()
        );
    }
}
