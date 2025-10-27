package com.example.backend.service;

import com.example.backend.dto.ReservationResponse;
import com.example.backend.entity.Reservation;
import com.example.backend.entity.ReservationStatus;
import com.example.backend.repository.ReservationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ReservationService {

    private final ReservationRepository repo;

    /** 기본: 해당 사용자의 모든 예약을 최신순으로 반환 */
    public List<ReservationResponse> getUserReservations(Long userNum) {
        requireUserNum(userNum);
        return mapToResponse(repo.findByUserNumOrderByRequestedAtDesc(userNum));
    }

    /**
     * 확장: 선택적 limit & 상태 필터 지원
     * @param userNum  대상 사용자
     * @param limit    최대 개수(<=0 이면 무시)
     * @param statuses 포함할 상태 집합(null/빈집합이면 모든 상태)
     */
    public List<ReservationResponse> getUserReservations(Long userNum,
                                                         @Nullable Integer limit,
                                                         @Nullable Set<ReservationStatus> statuses) {
        requireUserNum(userNum);

        List<Reservation> list = repo.findByUserNumOrderByRequestedAtDesc(userNum);
        Stream<Reservation> stream = list.stream();

        if (statuses != null && !statuses.isEmpty()) {
            stream = stream.filter(r -> statuses.contains(r.getStatus()));
        }
        if (limit != null && limit > 0) {
            stream = stream.limit(limit);
        }

        return stream.map(ReservationResponse::fromEntity).toList();
    }

    /* ───────── 내부 유틸 ───────── */
    private static void requireUserNum(Long userNum) {
        if (userNum == null) throw new IllegalArgumentException("userNum is required");
    }

    private static List<ReservationResponse> mapToResponse(List<Reservation> list) {
        return list.stream().map(ReservationResponse::fromEntity).toList();
    }
}
