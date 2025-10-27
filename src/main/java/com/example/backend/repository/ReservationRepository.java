// src/main/java/com/example/backend/repository/ReservationRepository.java
package com.example.backend.repository;

import com.example.backend.entity.Reservation;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ReservationRepository extends JpaRepository<Reservation, Long> {

    List<Reservation> findByUserNumOrderByRequestedAtDesc(Long userNum);

    Optional<Reservation> findByIdAndUserNum(Long id, Long userNum);
}
