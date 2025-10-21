// src/main/java/com/example/backend/repository/InquiryRepository.java
package com.example.backend.repository;

import com.example.backend.entity.InquiryEntity;
import com.example.backend.entity.InquiryStatus;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface InquiryRepository extends JpaRepository<InquiryEntity, Long> {

  @Query("""
    select i
    from InquiryEntity i
    where (:status is null or i.status = :status)
      and (
        :kw is null or :kw = '' or
        i.title   like concat('%', :kw, '%') or
        i.content like concat('%', :kw, '%') or
        i.email   like concat('%', :kw, '%') or
        i.name    like concat('%', :kw, '%') or
        i.userid  like concat('%', :kw, '%')
      )
    """)
  Page<InquiryEntity> search(@Param("status") InquiryStatus status,
                             @Param("kw") String kw,
                             Pageable pageable);
}
