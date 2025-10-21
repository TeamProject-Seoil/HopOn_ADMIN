// src/main/java/com/example/backend/repository/NoticeRepository.java
package com.example.backend.repository;

import com.example.backend.entity.*;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

public interface NoticeRepository extends JpaRepository<NoticeEntity, Long> {

    @Query("""
        SELECT n FROM NoticeEntity n
        WHERE (:q IS NULL OR n.title LIKE %:q% OR n.content LIKE %:q%)
          AND (:target IS NULL OR n.targetRole = :target)
          AND (:type IS NULL OR n.noticeType = :type)
        """)
    Page<NoticeEntity> search(
            @Param("q") String q,
            @Param("target") NoticeTarget target,
            @Param("type") NoticeType type,
            Pageable pageable
    );
}
