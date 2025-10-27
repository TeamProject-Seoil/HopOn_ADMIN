package com.example.backend.dto;

import com.example.backend.entity.Reservation;
import com.example.backend.entity.ReservationStatus;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.time.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ReservationResponse {

    private Long id;

    private String routeId;
    private String routeName;

    private String boardStopId;
    private String boardStopName;
    private String boardArsId;

    private String destStopId;
    private String destStopName;
    private String destArsId;

    private String direction;

    // 상태는 문자열로 내려주되, 엔티티가 Enum이면 toString() 사용
    private String status;

    @JsonProperty("requestedAt")
    private String requestedAtIso;

    @JsonProperty("updatedAt")
    private String updatedAtIso;

    /** 엔티티 → 응답 매핑 (KST 기준을 UTC Z로 직렬화) */
    public static ReservationResponse fromEntity(Reservation r) {
        return ReservationResponse.builder()
                .id(r.getId())
                .routeId(r.getRouteId())
                .routeName(r.getRouteName())
                .boardStopId(r.getBoardStopId())
                .boardStopName(r.getBoardStopName())
                .boardArsId(r.getBoardArsId())
                .destStopId(r.getDestStopId())
                .destStopName(r.getDestStopName())
                .destArsId(r.getDestArsId())
                .direction(r.getDirection())
                .status(resolveStatus(r))
                .requestedAtIso(toIsoOrNull(r.getRequestedAt()))
                .updatedAtIso(toIsoOrNull(r.getUpdatedAt()))
                .build();
    }

    private static String resolveStatus(Reservation r) {
        // 엔티티의 status 타입이 Enum 이든 String 이든 모두 대응
        try {
            Object st = r.getStatus();
            if (st == null) return null;
            if (st instanceof ReservationStatus rs) return rs.name();
            return st.toString();
        } catch (Exception ignored) {
            return null;
        }
    }

    /** LocalDateTime(KST 가정) -> UTC Z 문자열 */
    public static String toIsoOrNull(LocalDateTime t) {
        if (t == null) return null;
        ZoneId KST = ZoneId.of("Asia/Seoul");
        return t.atZone(KST).toInstant().toString(); // e.g. 2025-10-17T03:21:45Z
    }
}
