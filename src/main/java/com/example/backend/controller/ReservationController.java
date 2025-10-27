// src/main/java/com/example/backend/controller/ReservationController.java
package com.example.backend.controller;

import com.example.backend.dto.ReservationResponse;
import com.example.backend.entity.Reservation;
import com.example.backend.entity.UserEntity;
import com.example.backend.repository.ReservationRepository;
import com.example.backend.support.AuthUserResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Locale;
import java.util.Objects;

@RestController
@RequestMapping("/reservations")
@RequiredArgsConstructor
public class ReservationController {

    private final ReservationRepository reservationRepository;
    private final AuthUserResolver authUserResolver;

    /** 내 예약 목록 (최신순) */
    @GetMapping("/me")
    public ResponseEntity<List<ReservationResponse>> myReservations(Authentication authentication) {
        UserEntity me = authUserResolver.requireUser(authentication);
        var list = reservationRepository.findByUserNumOrderByRequestedAtDesc(me.getUserNum())
                .stream()
                .map(ReservationResponse::fromEntity)
                .toList();
        return ResponseEntity.ok(list);
    }

    /**
     * 전체 예약 목록 (관리자 전용)
     * 예: GET /reservations?page=0&size=20&sort=requestedAt,desc&status=CONFIRMED
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<ReservationResponse>> allReservations(
            @RequestParam(value = "status", required = false) String status,
            Pageable pageable
    ) {
        // 기본 정렬: requestedAt DESC
        Pageable pg = normalizePageable(pageable);

        Page<Reservation> page = reservationRepository.findAll(pg);

        // 상태 필터(옵션) — 리포지토리 의존 없이 메모리 필터
        if (status != null && !status.isBlank()) {
            final String want = status.trim().toUpperCase(Locale.ROOT);
            var filtered = page.getContent().stream()
                    .filter(r -> Objects.equals(
                            (r.getStatus() == null ? null : r.getStatus().name()), want))
                    .toList();
            Page<Reservation> filteredPage =
                    new PageImpl<>(filtered, pg, filtered.size());
            return ResponseEntity.ok(filteredPage.map(ReservationResponse::fromEntity));
        }

        return ResponseEntity.ok(page.map(ReservationResponse::fromEntity));
    }

    /**
     * 예약 단건 조회
     * - 관리자: 누구 것이든 조회 가능
     * - 일반 사용자: 본인 소유만 조회 가능(아니면 404)
     */
    @GetMapping("/{id}")
    public ResponseEntity<ReservationResponse> getOne(@PathVariable Long id,
                                                      Authentication authentication) {
        UserEntity me = authUserResolver.requireUser(authentication);

        var opt = reservationRepository.findById(id);
        if (opt.isEmpty()) return ResponseEntity.notFound().build();

        var r = opt.get();
        boolean isAdmin = (me.getRole() != null && me.getRole().name().equals("ROLE_ADMIN"));
        if (!isAdmin && !Objects.equals(r.getUserNum(), me.getUserNum())) {
            // 소유자 아니면 404로 숨김
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(ReservationResponse.fromEntity(r));
    }

    private Pageable normalizePageable(Pageable pageable) {
        if (pageable == null || pageable.isUnpaged()) {
            return PageRequest.of(0, 20, Sort.by(Sort.Order.desc("requestedAt")));
        }
        if (pageable.getSort().isUnsorted()) {
            return PageRequest.of(pageable.getPageNumber(), pageable.getPageSize(),
                    Sort.by(Sort.Order.desc("requestedAt")));
        }
        return pageable;
    }
}
