// src/main/java/com/example/backend/repository/DriverLicenseRepository.java
package com.example.backend.repository;

import com.example.backend.entity.DriverLicenseEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface DriverLicenseRepository extends JpaRepository<DriverLicenseEntity, Long> {

    /** 사용자 번호로 1:1 면허 조회 */
    Optional<DriverLicenseEntity> findByUser_UserNum(Long userNum);

    /** 해당 사용자에 대해 면허 레코드 존재 여부 */
    boolean existsByUser_UserNum(Long userNum);

    /** 면허번호 중복 여부 */
    boolean existsByLicenseNumber(String licenseNumber);

    /**
     * 업서트 시 사용: 현재 사용자 이외의 누군가가 동일 면허번호를 쓰는지 검사 (true면 중복)
     */
    boolean existsByLicenseNumberAndUser_UserNumNot(String licenseNumber, Long userNum);

    /** 면허번호로 조회 (필요 시) */
    Optional<DriverLicenseEntity> findByLicenseNumber(String licenseNumber);

    /** 사용자 탈퇴/정리 시 삭제 */
    void deleteByUser_UserNum(Long userNum);
}
