// src/main/java/com/example/backend/entity/Reservation.java
package com.example.backend.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "reservations")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Reservation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_num", nullable = false)
    private Long userNum;

    @Column(name = "route_id", nullable = false)
    private String routeId;

    @Column(name = "route_name", nullable = false)
    private String routeName;

    @Column(name = "board_stop_id")
    private String boardStopId;

    @Column(name = "board_stop_name")
    private String boardStopName;

    @Column(name = "board_ars_id")
    private String boardArsId;

    @Column(name = "dest_stop_id")
    private String destStopId;

    @Column(name = "dest_stop_name")
    private String destStopName;

    @Column(name = "dest_ars_id")
    private String destArsId;

    @Column(name = "direction")
    private String direction;

    /** ✅ enum을 문자열로 보관 (DB 컬럼: VARCHAR(16)) */
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private ReservationStatus status;

    @Column(name = "requested_at", nullable = false, insertable = false, updatable = false)
    private LocalDateTime requestedAt;

    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false)
    private LocalDateTime updatedAt;
}
